require('dotenv').config();
const express = require('express'), mongoose = require('mongoose'), bcrypt = require('bcryptjs'),
  jwt = require('jsonwebtoken'), path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
const SECRET = process.env.JWT_SECRET || 'change-me';
const PORT = process.env.PORT || 3000;

// ---------- Models ----------
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, lowercase: true },
  password: String,
  role: { type: String, enum: ['user', 'admin'], default: 'user' }
}));
const Product = mongoose.model('Product', new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  price: { type: Number, required: true, min: 0 },
  stock: { type: Number, default: 0, min: 0 },
  image: String,
  category: String
}));
const Order = mongoose.model('Order', new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  items: [{ product: mongoose.Schema.Types.ObjectId, name: String, price: Number, qty: Number }],
  total: Number,
  address: String,
  status: { type: String, enum: ['Placed', 'Shipped', 'Delivered', 'Cancelled'], default: 'Placed' }
}, { timestamps: true }));

// ---------- Helpers ----------
// auth() = any logged-in user; auth(['admin']) = admin only (role-based access)
const auth = roles => (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], SECRET); }
  catch { return res.status(401).json({ error: 'Please log in' }); }
  if (roles && !roles.includes(req.user.role)) return res.status(403).json({ error: 'Admins only' });
  next();
};
const wrap = fn => (req, res) => fn(req, res).catch(e => res.status(400).json({ error: e.code === 11000 ? 'Email already registered' : e.message }));
const session = u => ({
  token: jwt.sign({ id: u._id, role: u.role, name: u.name }, SECRET, { expiresIn: '7d' }),
  user: { name: u.name, role: u.role }
});

// ---------- Auth ----------
app.post('/api/register', wrap(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 6) throw new Error('Name, email and a 6+ character password are required');
  res.json(session(await User.create({ name, email, password: await bcrypt.hash(password, 10) })));
}));
app.post('/api/login', wrap(async (req, res) => {
  const u = await User.findOne({ email: (req.body.email || '').toLowerCase() });
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password))) return res.status(401).json({ error: 'Invalid email or password' });
  res.json(session(u));
}));

// ---------- Products ----------
app.get('/api/products', wrap(async (req, res) => {
  const q = req.query.q ? { name: new RegExp(String(req.query.q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') } : {};
  res.json(await Product.find(q).sort('-_id'));
}));
app.post('/api/products', auth(['admin']), wrap(async (req, res) => res.json(await Product.create(req.body))));
app.put('/api/products/:id', auth(['admin']), wrap(async (req, res) =>
  res.json(await Product.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true }))));
app.delete('/api/products/:id', auth(['admin']), wrap(async (req, res) => {
  await Product.findByIdAndDelete(req.params.id); res.json({ ok: true });
}));

// ---------- Orders ----------
app.post('/api/orders', auth(), wrap(async (req, res) => {
  const { items, address } = req.body;
  if (!Array.isArray(items) || !items.length || !address) throw new Error('Cart and delivery address are required');
  const lines = []; let total = 0;
  try {
    for (const i of items) {
      if (!Number.isInteger(i.qty) || i.qty < 1) throw new Error('Invalid quantity');
      // atomic stock check + decrement (prevents overselling)
      const p = await Product.findOneAndUpdate({ _id: i.product, stock: { $gte: i.qty } }, { $inc: { stock: -i.qty } });
      if (!p) throw new Error('An item is out of stock or no longer available');
      lines.push({ product: p._id, name: p.name, price: p.price, qty: i.qty });
      total += p.price * i.qty;
    }
  } catch (e) { // roll back stock already taken
    for (const l of lines) await Product.updateOne({ _id: l.product }, { $inc: { stock: l.qty } });
    throw e;
  }
  res.json(await Order.create({ user: req.user.id, items: lines, total, address }));
}));
app.get('/api/orders/mine', auth(), wrap(async (req, res) => res.json(await Order.find({ user: req.user.id }).sort('-createdAt'))));
app.get('/api/orders', auth(['admin']), wrap(async (req, res) => res.json(await Order.find().populate('user', 'name email').sort('-createdAt'))));
app.patch('/api/orders/:id/status', auth(['admin']), wrap(async (req, res) =>
  res.json(await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true, runValidators: true }))));

// ---------- Start + seed ----------
mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/shop').then(async () => {
  if (!(await User.findOne({ role: 'admin' })))
    await User.create({ name: 'Admin', email: process.env.ADMIN_EMAIL || 'admin@shop.com',
      password: await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 10), role: 'admin' });
  if (!(await Product.countDocuments()))
    await Product.insertMany([
      ['Wireless Headphones', 2499, 15, 'headphones'], ['Smart Watch', 3999, 10, 'watch'],
      ['Backpack', 1299, 25, 'backpack'], ['Mechanical Keyboard', 3499, 8, 'keyboard'],
      ['Water Bottle', 499, 40, 'bottle'], ['Desk Lamp', 899, 20, 'lamp']
    ].map(([name, price, stock, k]) => ({ name, price, stock, description: 'Quality ' + name.toLowerCase(),
      image: 'https://picsum.photos/seed/' + k + '/400/300', category: 'General' })));
  app.listen(PORT, () => console.log('Running at http://localhost:' + PORT));
}).catch(e => { console.error('DB connection failed:', e.message); process.exit(1); });
