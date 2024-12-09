import express from "express"
import dotenv from 'dotenv';
import bodyParser from "body-parser";
import path from 'path';
import session from "express-session";
import cookieParser from "cookie-parser";
import { fileURLToPath } from "url";
import neo4j from 'neo4j-driver';
import passport from "passport";
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import multer from 'multer';


//Add the changes like saving the email and things to session when using /user and etc.

dotenv.config();

const app = express()
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const driver = neo4j.driver(
    process.env.NEO4J_URI,
    neo4j.auth.basic(process.env.NEO4J_USERNAME, process.env.NEO4J_PASSWORD)
);
const Session = driver.session();
const upload = multer({ dest: 'uploads/' });

app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'Public')));
app.use(express.json());
app.set('views', path.join(__dirname, 'Public', 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}
));

app.use(passport.initialize());
app.use(passport.session());

const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
const redirectUri = 'http://localhost:3000/auth/google/callback';

passport.use(
    new GoogleStrategy(
        {
            clientID: googleClientId,
            clientSecret: googleClientSecret,
            callbackURL: redirectUri,
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const user = {
                    googleId: profile.id,
                    email: profile.emails[0].value,
                    name: profile.displayName,
                    avatarUrl:'/images/download.png', // Fallback to default
                };

                const result = await Session.run(
                    `MERGE (u:User {user_id: $googleId}) 
                     ON CREATE SET u.email = $email, u.name = $name, u.avatarUrl = $avatarUrl
                     RETURN u`,
                    user
                );

                const storedUser = result.records[0].get('u').properties;
                return done(null, storedUser);
            } catch (error) {
                console.error('Neo4j Error:', error);
                return done(error);
            }
        }

    )
);


passport.serializeUser((user, done) => {
    // Store user data in the session (typically the unique identifier)
    done(null, user.user_id); // Use Neo4j's `user_id` for session
});

passport.deserializeUser(async (userId, done) => {
    try {
        // Retrieve user from Neo4j using the stored `userId`
        const result = await Session.run(
            `MATCH (u:User {user_id: $userId}) RETURN u`,
            { userId }
        );

        if (result.records.length === 0) {
            return done(new Error('User not found'), null);
        }

        const user = result.records[0].get('u').properties;
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});


app.get('/', (req, res) => {
    res.render('index');
});

app.get('/login', (req, res) => {
    res.render('signup', { googleClientId });
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ message: 'Failed to log out' });
        }
        res.redirect('/');
    });
});

app.get('/auth/google/signin', passport.authenticate('google', { scope: ["profile", "email"] }));

app.get("/auth/google/callback",
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        // Save user data to the session
        req.session.user = req.user; // req.user comes from `deserializeUser`

        // Redirect to the dashboard
        res.redirect('/dashboard');
    }
);


app.post('/user', async (req, res) => {
    const { name, password } = req.body;

    try {
        // Check if the user exists in the database
        const existingUserQuery = `
            MATCH (u:User {name: $name})
            RETURN u
        `;
        const existingUserResult = await Session.run(existingUserQuery, { name });

        if (existingUserResult.records.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const user = existingUserResult.records[0].get('u').properties;

        // Validate password (add bcrypt for hashed passwords)
        if (user.password !== password) {
            return res.status(401).json({ success: false, message: 'Incorrect password' });
        }

        // Set the session and redirect to the dashboard
        req.session.user = {
            name: user.name,
            email: user.email,
            avatarUrl: user.avatarUrl || '/images/download.png',
        };
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Error interacting with Neo4j:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});


app.post('/add-user', async (req, res) => {
    const { name, email, password } = req.body;
    const defaultAvatar = '/images/download.png';

    try {
        const existingUserQuery = `
            MATCH (u:User {email: $email})
            RETURN u
        `;
        const existingUserResult = await Session.run(existingUserQuery, { email });

        if (existingUserResult.records.length > 0) {
            return res.status(400).send('User already exists with this email');
        }

        const createUserQuery = `
            MERGE (u:User {name: $name, email: $email, password: $password})
            SET u.avatarUrl = $defaultAvatar
            RETURN u
        `;
        const createUserResult = await Session.run(createUserQuery, { name, email, password, defaultAvatar });


        const createdUser = createUserResult.records[0].get('u').properties;

        req.session.user = {
            name: createdUser.name,
            email: createdUser.email,
            avatarUrl: createdUser.avatarUrl,
        };

        res.redirect('/dashboard');
    } catch (error) {
        console.error('Error adding user:', error);
        res.status(500).send('Error adding user: ' + error.message);
    }
});


app.get('/dashboard', async (req, res) => {
    const defaultAvatar = '/images/download.png';
    try {
        if (!req.session.user) {
            return res.redirect('/'); // Redirect if not logged in
        }

        // Set a default avatar if not provided
        req.session.user.avatarUrl = req.session.user.avatarUrl || defaultAvatar;

        const userName = req.session.user.name;

        // Query to fetch friends
        const friendsQuery = `
            MATCH (u:User {name: $userName})-[:FRIEND_WITH]->(friend:User)
            RETURN friend
        `;
        const friendsResult = await Session.run(friendsQuery, { userName });
        const friends = friendsResult.records.map(record => record.get('friend').properties);

        // Query to fetch groups
        const groupsQuery = `
            MATCH (u:User {name: $userName})-[:MEMBER_OF]->(group:Group)
            RETURN group
        `;
        const groupsResult = await Session.run(groupsQuery, { userName });
        const groups = groupsResult.records.map(record => record.get('group').properties);

        // Example recommendations (can be replaced with dynamic data)
        const recommendations = [
            { name: 'Dr. John Doe', link: '/mentors/suggestion1', description: 'AI Research' },
            { name: 'Deep Learning Project Ideas', link: '/projects/suggestion2', description: 'Collaboration' },
        ];

        // Render the dashboard
        res.render('dashboard', {
            user: req.session.user,
            friends: friends || [], // List of friends
            groups: groups || [],   // List of groups
            recommendations,
        });
    } catch (error) {
        console.error('Error rendering dashboard:', error);
        res.status(500).send('An error occurred.');
    }
});

app.get('/profile', async (req, res) => {
    try {
        if (!req.session.user) return res.redirect('/');

        const userName = req.session.user.name;

        // Check if the user exists as a Student or Teacher
        const roleCheckQuery = `
            MATCH (u:User {name: $userName})
            OPTIONAL MATCH (u)-[:HAS_ROLE]->(r)
            RETURN r
        `;
        const result = await Session.run(roleCheckQuery, { userName });

        const role = result.records[0].get('r');
        if (!role) {
            // If the user has no role, prompt to select
            return res.render('select-role', { user: req.session.user });
        }

        // Fetch profile details based on role (as before)
        const userType = role.labels[0].toLowerCase(); // Assuming labels are Student/Teacher
        req.session.user.userType = userType;

        res.render('profile', { user: req.session.user });
    } catch (error) {
        console.error('Error checking role:', error);
        res.status(500).send('An error occurred.');
    }
});


app.post('/select-role', async (req, res) => {
    const { role } = req.body; // Get the role from the request body
    try {
        // Log the role for debugging purposes
        console.log("Role received:", role);
        
        // Check if the session exists and the user is logged in
        if (!req.session.user) {
            console.log("User not authenticated");
            return res.status(401).send('Unauthorized');
        }

        const userName = req.session.user.name;
        const userEmail = req.session.user.email;

        let createNodeQuery;

        // Check and set up role-specific queries
        if (role === "Student") {
            createNodeQuery = `
                MATCH (u:User {name: $userName})
                CREATE (s:Student {
                    name: $userName,
                    email: $userEmail,
                    cgpa: 0.0,
                    skills: [],
                    university: "Not specified"
                })
                CREATE (u)-[:HAS_ROLE]->(s)
            `;
        } else if (role === "Teacher") {
            createNodeQuery = `
                MATCH (u:User {name: $userName})
                CREATE (t:Teacher {
                    name: $userName,
                    email: $userEmail,
                    institution: "Not specified",
                    highestDegree: "Not specified",
                    researchInterests: []
                })
                CREATE (u)-[:HAS_ROLE]->(t)
            `;
        } else {
            console.log("Invalid role received:", role);
            return res.status(400).send('Invalid role selected');
        }

        // Run the query in Neo4j
        await Session.run(createNodeQuery, { userName, userEmail });

        // Update the session with the user's type
        req.session.user.userType = role.toLowerCase();

        // Respond with a success message
        res.status(200).send('Role set successfully');
    } catch (error) {
        console.error('Error creating role node:', error);
        res.status(500).send('Failed to create role node');
    }
});

app.post('/update-role', async (req, res) => {
    const { newRole } = req.body; // Get the new role from the request body
    try {
        if (!req.session.user) {
            console.log("User not authenticated");
            return res.status(401).send('Unauthorized');
        }

        const userName = req.session.user.name;
        const userEmail = req.session.user.email;

        let roleNode;
        let createNodeQuery;
        
        // Remove the existing role node if present
        await Session.run(`
            MATCH (u:User {name: $userName})-[r:HAS_ROLE]->(role)
            DELETE r
        `, { userName });

        // Check and set up role-specific queries
        if (newRole === "Student") {
            createNodeQuery = `
                MATCH (u:User {name: $userName})
                CREATE (s:Student {
                    name: $userName,
                    email: $userEmail,
                    cgpa: 0.0,
                    skills: [],
                    university: "Not specified"
                })
                CREATE (u)-[:HAS_ROLE]->(s)
            `;
        } else if (newRole === "Teacher") {
            createNodeQuery = `
                MATCH (u:User {name: $userName})
                CREATE (t:Teacher {
                    name: $userName,
                    email: $userEmail,
                    institution: "Not specified",
                    highestDegree: "Not specified",
                    researchInterests: []
                })
                CREATE (u)-[:HAS_ROLE]->(t)
            `;
        } else {
            console.log("Invalid role received:", newRole);
            return res.status(400).send('Invalid role selected');
        }

        // Run the query to create the new role node
        await Session.run(createNodeQuery, { userName, userEmail });

        // Update the session with the user's new type
        req.session.user.userType = newRole.toLowerCase();

        // Respond with a success message
        res.status(200).send('Role updated successfully');
    } catch (error) {
        console.error('Error updating role:', error);
        res.status(500).send('Failed to update role');
    }
});

process.on("exit", async () => {
    await driver.close();
});


const PORT = process.env.PORT;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
