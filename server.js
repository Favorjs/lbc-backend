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
  role: { type: String, enum: ['admin', 'group_leader', 'deputy_leader'], default: 'group_leader' },
  group: { 
    type: String, 
    enum: ['A', 'B'], 
    required: true  // Changed to required for all
  },
  isAdmin: { type: Boolean, default: false }
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

const authorizeAdmin = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).send('Admin access required');
  }
  next();
};

// Use it like this in admin routes:
app.get('/api/admin/members', authenticate, authorizeAdmin, async (req, res) => {
  // Admin-only member listing
});

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

  // if (await User.countDocuments({ isAdmin: true }) === 0) {
  //   const hashedPassword = await bcrypt.hash('admin123', 10);
  //   await User.create({
  //     name: 'Super Admin',
  //     email: 'admin@church.com',
  //     password: hashedPassword,
  //     phone: '00000000000',
  //     isAdmin: true,
  //     role: 'admin'
  //   });
  // }
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

// Get all members (admin can see all, others see only their group)
app.get('/api/members', authenticate, async (req, res) => {
  try {
    let query = {};
    if (req.user.role !== 'admin') {
      query.group = req.user.group;
    }
    
    const members = await Member.find(query);
    res.json(members);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.post('/api/members', authenticate, async (req, res) => {
  try {
    const memberData = {
      name: req.body.name,
      phone: req.body.phone,
      group: req.user.role === 'admin' ? req.body.group : req.user.group
    };
    
    const member = new Member(memberData);
    await member.save();
    res.status(201).json(member);
  } catch (err) {
    res.status(400).json({ message: err.message });
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

// In your server.js
app.post('/api/reports', authenticate, async (req, res) => {
  try {
    const { month, year, contacts, isLeaderReport } = req.body;
    const userId = req.user._id;
    const group = req.user.group;

    // Validate input
    if (!month || !year || !contacts) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    // Find existing report or create new one
    let report = await Report.findOne({ month, year, group });

    if (!report) {
      report = new Report({
        month,
        year,
        group,
        leaderReport: { leaderId: userId, contacts: [] },
        deputyReport: { leaderId: userId, contacts: [] }
      });
    }

    // Update the appropriate report based on user role
    if (isLeaderReport) {
      report.leaderReport = {
        leaderId: userId,
        contacts: contacts.map(contact => ({
          memberId: contact.memberId,
          contacted: contact.contacted,
          feedback: contact.feedback
        })),
        submittedAt: new Date()
      };
    } else {
      report.deputyReport = {
        leaderId: userId,
        contacts: contacts.map(contact => ({
          memberId: contact.memberId,
          contacted: contact.contacted,
          feedback: contact.feedback
        })),
        submittedAt: new Date()
      };
    }

    // Automatically finalize if both reports are submitted
    if (report.leaderReport.contacts.length > 0 && report.deputyReport.contacts.length > 0) {
      report.finalSubmission = true;
      report.submittedAt = new Date();
    }

    await report.save();
    res.status(201).json(report);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Add this route to your backend
app.post('/api/reports', authenticate, async (req, res) => {
  try {
    const { month, year, contacts } = req.body;
    const userId = req.user._id;
    const userRole = req.user.role;
    const group = req.user.group;

    // Validate input
    if (!month || !year || !contacts) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    // Find existing report or create new one
    let report = await Report.findOne({ month, year, group });

    if (!report) {
      report = new Report({
        month,
        year,
        group,
        leaderReport: { leaderId: userId, contacts: [] },
        deputyReport: { leaderId: userId, contacts: [] }
      });
    }

    // Update the appropriate report based on user role
    if (userRole === 'group_leader') {
      report.leaderReport = {
        leaderId: userId,
        contacts: contacts.map(contact => ({
          memberId: contact.memberId,
          contacted: contact.contacted,
          feedback: contact.feedback
        })),
        submittedAt: new Date()
      };
    } else if (userRole === 'deputy_leader') {
      report.deputyReport = {
        leaderId: userId,
        contacts: contacts.map(contact => ({
          memberId: contact.memberId,
          contacted: contact.contacted,
          feedback: contact.feedback
        })),
        submittedAt: new Date()
      };
    } else {
      return res.status(403).json({ message: 'Only leaders can submit reports' });
    }

    await report.save();
    res.status(201).json(report);
  } catch (err) {
    res.status(500).json({ message: err.message });
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

// Admin login
app.post('/api/admin/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email, isAdmin: true });
  if (!user) return res.status(400).send('Admin not found');

  const validPass = await bcrypt.compare(req.body.password, user.password);
  if (!validPass) return res.status(400).send('Invalid password');

  const token = jwt.sign(
    { _id: user._id, role: user.role, isAdmin: true },
    process.env.JWT_SECRET,
    { expiresIn: '1d' }
  );
  res.header('Authorization', token).send({ token, user });
});


// Add this route in your backend (server.js)
app.post('/api/admin/register', [
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('secretKey').equals(process.env.ADMIN_SECRET_KEY)
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    // Check if admin already exists
    const adminExists = await User.findOne({ email: req.body.email, isAdmin: true });
    if (adminExists) return res.status(400).send('Admin already exists');

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
      phone: req.body.phone,
      isAdmin: true,
      role: 'admin' // You might want to keep this for backward compatibility
    });
    
    await user.save();
    res.status(201).send('Admin created successfully');
    
  } catch (err) {
    res.status(400).send(err.message);
  }
});
// Regular user login remains the same
// Add to server.js


// Update the individual member report endpoint
app.post('/api/reports/member', authenticate, async (req, res) => {
  try {
    const { month, year, memberId, contacted, feedback, isLeaderReport } = req.body;
    const userId = req.user._id;
    const group = req.user.group;  // Get group from authenticated user

    // Validate input
    if (!month || !year || !memberId) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    // Validate group exists
    if (!group) {
      return res.status(400).json({ message: 'User group is missing' });
    }

    // Find existing report or create new one
    let report = await Report.findOne({ month, year, group });

    if (!report) {
      report = new Report({
        month,
        year,
        group,  // Ensure group is set here
        leaderReport: { leaderId: userId, contacts: [] },
        deputyReport: { leaderId: userId, contacts: [] }
      });
    }

    // Update the appropriate report
    if (isLeaderReport) {
      report.leaderReport.contacts = report.leaderReport.contacts.filter(
        c => c.memberId.toString() !== memberId
      );
      report.leaderReport.contacts.push({ memberId, contacted, feedback });
    } else {
      report.deputyReport.contacts = report.deputyReport.contacts.filter(
        c => c.memberId.toString() !== memberId
      );
      report.deputyReport.contacts.push({ memberId, contacted, feedback });
    }

    await report.save();
    res.status(201).json(report);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// Add this to your backend (server.js)
app.post('/api/reports/member', authenticate, async (req, res) => {
  try {
    const { month, year, memberId, contacted, feedback, isLeaderReport } = req.body;
    const userId = req.user._id;
    const group = req.user.group;

    // Find or create report for this month/year/group
    let report = await Report.findOne({ month, year, group });
    if (!report) {
      report = new Report({
        month,
        year,
        group,
        leaderReport: { leaderId: userId, contacts: [] },
        deputyReport: { leaderId: userId, contacts: [] }
      });
    }

    // Update the appropriate report
    if (isLeaderReport) {
      // Remove existing contact if it exists
      report.leaderReport.contacts = report.leaderReport.contacts.filter(
        c => c.memberId.toString() !== memberId
      );
      
      // Add new contact
      report.leaderReport.contacts.push({ memberId, contacted, feedback });
    } else {
      // Remove existing contact if it exists
      report.deputyReport.contacts = report.deputyReport.contacts.filter(
        c => c.memberId.toString() !== memberId
      );
      
      // Add new contact
      report.deputyReport.contacts.push({ memberId, contacted, feedback });
    }

    await report.save();
    res.status(201).json(report);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.get('/api/test', (req, res) => {
  res.send('Server is running');
});
// Start server and seed data
const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  // await seedInitialData();
});