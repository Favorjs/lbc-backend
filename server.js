require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const ExcelJS = require('exceljs');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/church_reports', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.connection.on('connected', () => console.log('Connected to MongoDB'));

// Models
const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'group_leader', 'deputy_leader'], required: true },
  group: { type: String, enum: ['A', 'B'], required: true }
}));

const Member = mongoose.model('Member', new mongoose.Schema({
  name: { type: String, required: true },
  phone: { type: String, required: true },
  group: { type: String, enum: ['A', 'B'], required: true }
}));

const Report = mongoose.model('Report', new mongoose.Schema({
  month: { type: String, required: true },
  year: { type: Number, required: true },
  group: { type: String, enum: ['A', 'B'], required: true },
  leaderReport: {
    leaderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    contacts: [{
      memberId: { type: mongoose.Schema.Types.ObjectId, ref: 'Member' },
      contacted: { type: Boolean, default: false },
      feedback: { type: String }
    }],
    submittedAt: { type: Date, default: Date.now }
  },
  deputyReport: {
    leaderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    contacts: [{
      memberId: { type: mongoose.Schema.Types.ObjectId, ref: 'Member' },
      contacted: { type: Boolean, default: false },
      feedback: { type: String }
    }],
    submittedAt: { type: Date, default: Date.now }
  },
  finalSubmission: { type: Boolean, default: false },
  submittedAt: { type: Date }
}));

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  port:465,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Middleware
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).send('Access denied');

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send('Invalid token');
  }
};

const authorize = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).send('Forbidden');
  }
  next();
};

// Seed initial data (run once)
// const seedInitialData = async () => {
//   if (await User.countDocuments() === 0) {
//     const hashedPassword = await bcrypt.hash('admin123', 10);
//     await User.create([
//       { name: 'Admin', email: 'admin@church.com', password: hashedPassword, role: 'admin', group: 'A', phone: '00000000000' },
//       { name: 'Pastor Dedun', email: 'dedun@church.com', password: hashedPassword, role: 'group_leader', group: 'A', phone: '11111111111' },
//       { name: 'Minister Nony', email: 'nony@church.com', password: hashedPassword, role: 'deputy_leader', group: 'A', phone: '22222222222' },
//       { name: 'Pastor Nike', email: 'nike@church.com', password: hashedPassword, role: 'group_leader', group: 'B', phone: '33333333333' },
//       { name: 'Minister Daniel', email: 'daniel@church.com', password: hashedPassword, role: 'deputy_leader', group: 'B', phone: '44444444444' }
//     ]);

//     const groupAMembers = [
//       { name: 'Bro Buchy', phone: '09038684245', group: 'A' },
//       { name: 'Sis Blessing Ogechi', phone: '09072036013', group: 'A' },
//       // Add all other group A members...
//     ];

//     const groupBMembers = [
//       { name: 'Bro Andrew', phone: '081204505088', group: 'B' },
//       { name: 'Sis Damilola', phone: '08068891674', group: 'B' },
//       // Add all other group B members...
//     ];

//     await Member.insertMany([...groupAMembers, ...groupBMembers]);
//   }
// };

// Routes
app.post('/api/register', [
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('role').isIn(['admin', 'group_leader', 'deputy_leader'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
      role: req.body.role,
      
      group: req.body.group,
      phone: req.body.phone
    });
    await user.save();
    res.status(201).send('User created');
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.post('/api/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).send('Email not found');

  const validPass = await bcrypt.compare(req.body.password, user.password);
  if (!validPass) return res.status(400).send('Invalid password');

  const token = jwt.sign(
    { _id: user._id, role: user.role, group: user.group },
    process.env.JWT_SECRET,
    { expiresIn: '1d' }
  );
  res.header('Authorization', token).send({ token, user });
});

app.get('/api/members', authenticate, async (req, res) => {
  const members = await Member.find({ group: req.user.group });
  res.send(members);
});
app.post('/api/members', [
  authenticate,
  authorize(['admin', 'group_leader']),
  body('name').notEmpty().trim(),
  body('phone').notEmpty().trim(),
  body('group').isIn(['A', 'B'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const member = new Member({
      name: req.body.name,
      phone: req.body.phone,
      group: req.user.role === 'admin' ? req.body.group : req.user.group
    });
    
    await member.save();
    res.status(201).send(member);
  } catch (err) {
    res.status(400).send(err.message);
  }
});


app.put('/api/members/:id', [
  authenticate,
  authorize(['admin', 'group_leader']),
  body('name').notEmpty().trim(),
  body('phone').notEmpty().trim(),
  body('group').isIn(['A', 'B'])
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const member = await Member.findByIdAndUpdate(
      req.params.id,
      {
        name: req.body.name,
        phone: req.body.phone,
        group: req.user.role === 'admin' ? req.body.group : req.user.group
      },
      { new: true }
    );
    
    if (!member) return res.status(404).send('Member not found');
    res.send(member);
  } catch (err) {
    res.status(400).send(err.message);
  }
});
// Delete member
app.delete('/api/members/:id', [
  authenticate,
  authorize(['admin', 'group_leader'])
], async (req, res) => {
  try {
    const member = await Member.findByIdAndDelete(req.params.id);
    if (!member) return res.status(404).send('Member not found');
    res.send(member);
  } catch (err) {
    res.status(400).send(err.message);
  }
});
// In your /api/reports endpoint
app.get('/api/reports', authenticate, async (req, res) => {
  try {
    let query = {};
    
    // For non-admins, only show their group's reports
    if (req.user.role !== 'admin') {
      query.group = req.user.group;
    }

    // Apply filters from query params
    if (req.query.month) query.month = req.query.month;
    if (req.query.year) query.year = req.query.year;
    if (req.query.group && req.query.group !== 'All') {
      query.group = req.query.group;
    }

    const reports = await Report.find(query)
      .populate('leaderReport.leaderId', 'name email')
      .populate('deputyReport.leaderId', 'name email')
      .populate('leaderReport.contacts.memberId', 'name phone group')
      .populate('deputyReport.contacts.memberId', 'name phone group')
      .sort({ year: -1, month: -1 }); // Sort by newest first

    if (!reports.length) {
      return res.status(404).json({ message: 'No reports found for the selected criteria' });
    }

    res.json(reports);
  } catch (err) {
    console.error('Error fetching reports:', err);
    res.status(500).json({ 
      message: 'Server error while fetching reports',
      error: err.message 
    });
  }
});

app.post('/api/reports/finalize', authenticate, authorize(['group_leader']), [
  body('month').isString(),
  body('year').isNumeric()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const report = await Report.findOneAndUpdate(
      {
        month: req.body.month,
        year: req.body.year,
        group: req.user.group
      },
      { finalSubmission: true, submittedAt: new Date() },
      { new: true }
    );

    if (!report) return res.status(404).send('Report not found');

    // Notify admin
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.email) {
      await transporter.sendMail({
        to: admin.email,
        subject: `Final Report Submitted for ${req.body.month} ${req.body.year}`,
        text: `Group ${req.user.group} has submitted their final report for ${req.body.month} ${req.body.year}.`
      });
    }

    res.send(report);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.get('/api/reports', authenticate, async (req, res) => {
  try {
    let query = {};
    if (req.user.role !== 'admin') {
      query.group = req.user.group;
    }

    if (req.query.month) query.month = req.query.month;
    if (req.query.year) query.year = req.query.year;

    const reports = await Report.find(query)
      .populate('leaderReport.leaderId', 'name')
      .populate('deputyReport.leaderId', 'name')
      .populate('leaderReport.contacts.memberId', 'name phone')
      .populate('deputyReport.contacts.memberId', 'name phone');

    res.send(reports);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.get('/api/reports/export', authenticate, authorize(['admin']), async (req, res) => {
  try {
    const reports = await Report.find()
      .populate('leaderReport.leaderId', 'name')
      .populate('deputyReport.leaderId', 'name')
      .populate('leaderReport.contacts.memberId', 'name phone')
      .populate('deputyReport.contacts.memberId', 'name phone');

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Reports');

    // Add headers
    worksheet.columns = [
      { header: 'Month', key: 'month', width: 10 },
      { header: 'Year', key: 'year', width: 10 },
      { header: 'Group', key: 'group', width: 10 },
      { header: 'Member Name', key: 'memberName', width: 25 },
      { header: 'Member Phone', key: 'memberPhone', width: 15 },
      { header: 'Leader Contacted', key: 'leaderContacted', width: 15 },
      { header: 'Leader Feedback', key: 'leaderFeedback', width: 30 },
      { header: 'Deputy Contacted', key: 'deputyContacted', width: 15 },
      { header: 'Deputy Feedback', key: 'deputyFeedback', width: 30 },
      { header: 'Final Submission', key: 'finalSubmission', width: 15 }
    ];

    // Add data
    reports.forEach(report => {
      report.leaderReport.contacts.forEach(contact => {
        const deputyContact = report.deputyReport?.contacts?.find(c => 
          c.memberId._id.toString() === contact.memberId._id.toString()
        );

        worksheet.addRow({
          month: report.month,
          year: report.year,
          group: report.group,
          memberName: contact.memberId.name,
          memberPhone: contact.memberId.phone,
          leaderContacted: contact.contacted ? 'Yes' : 'No',
          leaderFeedback: contact.feedback || '',
          deputyContacted: deputyContact?.contacted ? 'Yes' : 'No',
          deputyFeedback: deputyContact?.feedback || '',
          finalSubmission: report.finalSubmission ? 'Yes' : 'No'
        });
      });
    });

    // Set response headers
    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
      'Content-Disposition',
      'attachment; filename=church_reports.xlsx'
    );

    // Send the workbook
    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Start server and seed data
const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  // await seedInitialData();
});