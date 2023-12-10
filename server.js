
const path = require('path');
const db=require('./dbConfig');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const multer = require('multer');

const app = express();
 
const upload = multer();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
 
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


app.use(express.static(path.join(__dirname, 'public')));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());


app.use((req, res, next) => {
    res.locals.user = req.user || null;
    next();
});


// router.use(ensureAuthenticated);
const nodemailer = require('nodemailer');

// Configure Nodemailer (replace with your actual email service configuration)
const transporter = nodemailer.createTransport({
    host: "sandbox.smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: "cbbf3bb09ff1e1",
      pass: "9f34b749594d9f"
    }
  });

const Roles = {
    Admin: 'Admin',
    Manager: 'Manager',
    User: 'User',
    Technician: 'Technician'
};


function checkRole(role) {
    return (req, res, next) => {
        if (req.user && req.user.role === role) {
            next();
        } else {
            res.status(403).send('Access denied');
        }
    };
}


app.get('/', ensureAuthenticated,function(req, res, next) {
	if (req.isAuthenticated()) { 
        res.redirect('/home'); 
    } else {
        res.render('login');
    }
});

app.get('/home', (req, res) => {
    res.render('home', { title: 'Home' });
});

app.get('/addNotifications',ensureAuthenticated, function(req, res, next) {
	res.render('addNotifications', { title: 'Home' });
});
 
app.get('/getNotifications', ensureAuthenticated, function(req, res) {
    // SQL query to fetch notifications not linked to any work order
    const query = `
        SELECT * FROM notifications 
        WHERE id NOT IN (
            SELECT notification_id FROM work_orders
        )`;

    db.query(query, function(err, result) {
        if (err) {
            console.error('Error fetching notifications:', err);
            return res.status(500).send('Error fetching notifications');
        }
        console.log(result);
        res.render('getNotifications', { title: 'notifications', notificationData: result });
    });
});

app.get('/equipment', ensureAuthenticated, function(req, res){
	db.query("SELECT * FROM equipment", function (err, result) {
		if (err) throw err;
		console.log(result);
		res.render('equipment', { title: 'equipment', equipmentData: result});
	});
});

app.get('/workOrders', ensureAuthenticated, function(req, res){
	db.query("SELECT * FROM work_orders", function (err, result) {
		if (err) throw err;
		console.log(result);
		res.render('workOrders', { title: 'workOrders', workOrdersData: result});
	});
});

app.post('/update-work-order-status', (req, res) => {
    const { id, status } = req.body;
    // Updating the status in the database
    const updateQuery = 'UPDATE work_orders SET status = ? WHERE id = ?';
    db.query(updateQuery, [status, id], (err, result) => {
        if (err) {
            console.error('Error updating status:', err);
            return res.status(500).json({ message: 'Error updating status' });
        }
        res.json({ message: 'Status updated successfully' });
    });
});


app.post('/addNotifications', function(req, res, next) {
    if (!req.user) {
        return res.status(403).send('User not authenticated');
    }

    var description = req.body.description;
    var priority = req.body.priority;
    var created_by = req.user.username; 
    var user_id = req.user.id;
    
    console.log(user_id);

    // Server-side validation
    if (!description || !created_by || !priority) {
        // Responding with an error message if any field is empty
        return res.status(400).render('addNotifications', { error: "All fields are required." });
    }

    // Validating that priority is either 'High', 'Medium', or 'Low'
    const validPriorities = ['High', 'Medium', 'Low'];
    if (!validPriorities.includes(priority)) {
        return res.status(400).render('addNotifications', { error: "Invalid priority selected." });
    }

    var sql = "INSERT INTO notifications (user_id,description, created_by, priority, reported_at) VALUES (?, ?, ?,?, NOW())";
    db.query(sql, [user_id,description, created_by, priority], function(err, result) {
        if (err) {
            console.error(err.message);
            res.status(500).render('addNotifications', { error: "There was an error saving the work request." });
        } else {
            console.log('Record inserted', result);
            res.render('addNotifications', { success: "Work request created successfully!" });
        }
    });
});

// Configuring Passport
passport.use(new LocalStrategy(
    (username, password, done) => {
        db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
            if (err) { return done(err); }

            const user = results[0];
            if (!user) {
                return done(null, false, { message: 'Incorrect username.' });
            }

            bcrypt.compare(password, user.password, (err, res) => {
                if (res) {
                    return done(null, user);
                } else {
                    return done(null, false, { message: 'Incorrect password.' });
                }
            });
        });
    }
));


passport.serializeUser((user, done) => {
    done(null, user.username);
});

passport.deserializeUser((username, done) => {
    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) {
            return done(err);
        }
        const user = results[0] || false;
        done(null, user);
    });
});


// Serving login page
app.get('/login', function(req, res, next) {
	res.render('login', { title: 'Login' });
});

// Handling login POST
app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login'
}));

// Handling logout
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        // Redirect the user after successful logout
        res.redirect('/login');
    });
});

// Middleware to protect routes
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

// Protected route
app.get('/', ensureAuthenticated, (req, res) => {
    res.send('Logged in user: ' + req.user.username);
});


app.get('/register', ensureAuthenticated, (req, res, next) => {
    res.render('register', { title: 'Register' });
  });
  

// Registering a new user 
app.post('/register', async (req, res) => {
    console.log("Register route hit");
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const username = req.body.username;
        const email = req.body.email;
        const role = req.body.role; 

        // role validation
        if (![ 'User', 'Admin', 'Manager', 'Technician' ].includes(role)) {
            return res.status(400).send('Invalid role');
        }

        console.log(username, email, role);

        const checkUserQuery = 'SELECT * FROM users WHERE username = ?';
        db.query(checkUserQuery, [username], async (err, result) => {
            if (err) {
                res.send('Error in registration');
            } else if (result.length > 0) {
                // Username already exists
                res.send('Username already taken');
            } else {
                // Insert the new user as username is not taken
                const insertQuery = 'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)';
                db.query(insertQuery, [username, hashedPassword, email, role], (err, result) => {
                    if (err) {
                        console.error("Registration error:", err);
                        res.send('Error in registration');
                    } else {
                        res.render('register', { success: "User has been created successfully!" });
                    }
                });
            }
        });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).send("An error occurred during registration");
    }
});

function executeQuery(sql, values) {
    return new Promise((resolve, reject) => {
        db.query(sql, values, (err, results) => {
            if (err) {
                reject(err);
            } else {
                resolve(results);
            }
        });
    });
}

app.post('/create-work-order',  upload.none(), async (req, res) => {
    try {
        const { notificationId, description, plannedHours, assignedPersonnel, dateScheduled, status } = req.body;
        
        if (!notificationId || !description || !plannedHours || !assignedPersonnel || !dateScheduled || !status) {
            return res.status(400).send('Missing required fields');
        }

         // Query for the username of the assigned personnel
         const username = 'SELECT username FROM users WHERE id = ? AND role = "Technician"';
         const usernameResults = await executeQuery(username, [assignedPersonnel]);
 
         console.log(username);
 
         if (usernameResults.length === 0) {
             console.error(`No user found with ID: ${assignedPersonnel}`);
             return res.status(404).send('Assigned personnel not found');
         }
 
         const assignedUsername = usernameResults[0].username;
 
         if (!assignedUsername) {
             throw new Error('Assigned personnel not found');
         }


        // Inserting the work order data into the work_orders table
        const insertQuery = 'INSERT INTO work_orders (notification_id, description, planned_hours, assigned_personnel, date_scheduled, status, assignedUsername) VALUES (?, ?, ?, ?, ?, ?, ?)';
        await db.query(insertQuery, [notificationId, description, plannedHours, assignedPersonnel, dateScheduled, status, assignedUsername]);

        // Query for the email of the assigned personnel
        const emailQuery = 'SELECT email FROM users WHERE id = ? AND role = "Technician"';
        const emailResults = await executeQuery(emailQuery, [assignedPersonnel]);

        console.log(emailResults);

        if (emailResults.length === 0) {
            console.error(`No user found with ID: ${assignedPersonnel}`);
            return res.status(404).send('Assigned personnel not found');
        }

        const assignedEmail = emailResults[0].email;

        if (!assignedEmail) {
            throw new Error('Assigned personnel not found');
        }


        // Send an email to the assigned technician
        const emailBody = `
            A new work order has been assigned to you.
            Description: ${description}
            Date Scheduled: ${dateScheduled}
        `;
        await transporter.sendMail({
            from: 'support@assetmanagement.com',
            to: assignedEmail, 
            subject: 'New Work Order Assigned Please Login To Your profile and see the new work order',
            text: emailBody
        });
        res.json({ message: "Work request created successfully!" });


    } catch (error) {
        console.error('Error creating work order:', error);
        res.status(500).send('An error occurred while creating the work order');
    }
});


app.get('/fetch-personnel', function(req, res) {
    db.query("SELECT id, username, email FROM users WHERE role = 'Technician'", function (err, result) {
        if (err) {
            console.error('Error fetching personnel:', err);
            return res.status(500).send('Error fetching personnel');
        }
        console.log(result);
        res.json(result); 
    });
});

app.get('/assignedWorkOrders', (req, res) => {
    if (!req.isAuthenticated() || req.user.role !== 'Technician') {
        return res.status(403).send('Access denied');
    }

    const technicianId = req.user.id; 
    const query = 'SELECT * FROM work_orders WHERE assigned_personnel = ?';

    db.query(query, [technicianId], (err, workOrders) => {
        if (err) {
            console.error('Error fetching work orders:', err);
            return res.status(500).send('Error fetching work orders');
        }

        res.render('assignedWorkOrders', { workOrders: workOrders });
    });
});

app.listen(3000);
console.log('Node app is running on port 3000');
