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
            const session = driver.session();
            try {
                const user = {
                    googleId: profile.id,
                    email: profile.emails[0].value,
                    name: profile.displayName,
                    avatarUrl: profile.photos[0]?.value || '/images/download.png', // Use Google profile photo or fallback
                };
                
                // Save or update the user in the database
                const result = await session.run(
                    `MERGE (u:User {user_id: $googleId}) 
                     ON CREATE SET u.email = $email, u.name = $name, u.avatarUrl = $avatarUrl
                     ON MATCH SET u.avatarUrl = $avatarUrl
                     RETURN u`,
                    user
                );

                const storedUser = result.records[0].get('u').properties;
                return done(null, storedUser);
            } catch (error) {
                console.error('Neo4j Error:', error);
                return done(error);
            } finally {
                await session.close();
            }
        }
    )
);

passport.serializeUser((user, done) => {
    done(null, user.user_id);
});

passport.deserializeUser(async (userId, done) => {
    const session = driver.session();
    try {
        const result = await session.run(
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
    } finally {
        await session.close();
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
    async (req, res) => {
        const session = driver.session();
        try {
            const userId = req.user.user_id; // From deserializeUser
            const roleQuery = `
                MATCH (u:User {user_id: $userId})
                OPTIONAL MATCH (u)-[:HAS_ROLE]->(role)
                RETURN role
            `;
            const result = await session.run(roleQuery, { userId });

            const role = result.records[0]?.get('role');

            if (role) {
                // If role exists, redirect to the dashboard
                req.session.user = {
                    ...req.user, // Existing user data
                    role: role.labels[0].toLowerCase(), // e.g., 'student' or 'teacher'
                };
                return res.redirect('/dashboard');
            }

            // If no role exists, redirect to select role
            req.session.user = req.user; // Save user info in session
            res.redirect('/select-role'); // Redirect to role selection
        } catch (error) {
            console.error('Error checking user role:', error);
            res.status(500).send('Internal Server Error');
        } finally {
            await session.close();
        }
    }
);


app.post('/user', async (req, res) => {
    const { name, password } = req.body;
    const session = driver.session();

    try {
        const existingUserQuery = `MATCH (u:User {name: $name}) RETURN u`;
        const existingUserResult = await session.run(existingUserQuery, { name });

        const roleCheckQuery = `
            MATCH (u:User {name: $name})
            OPTIONAL MATCH (u)-[:HAS_ROLE]->(r)
            RETURN r
        `;
        const result = await Session.run(roleCheckQuery, { name });

        const role = result.records[0].get('r');

        // Fetch profile details based on role (as before)
        const userType = role.labels[0].toLowerCase(); // Assuming labels are Student/Teacher

        if (existingUserResult.records.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const user = existingUserResult.records[0].get('u').properties;

        if (user.password !== password) {
            return res.status(401).json({ success: false, message: 'Incorrect password' });
        }

        req.session.user = {
            name: user.name,
            email: user.email,
            avatarUrl: user.avatarUrl || '/images/download.png',
            role: userType
        };
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Error interacting with Neo4j:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    } finally {
        await session.close();
    }
});

app.post('/add-user', async (req, res) => {
    const { name, email, password } = req.body;
    const defaultAvatar = '/images/download.png';
    const session = driver.session();

    try {
        const existingUserQuery = `MATCH (u:User {email: $email}) RETURN u`;
        const existingUserResult = await session.run(existingUserQuery, { email });

        if (existingUserResult.records.length > 0) {
            return res.status(400).send('User already exists with this email');
        }

        const createUserQuery = `
            MERGE (u:User {name: $name, email: $email, password: $password})
            SET u.avatarUrl = $defaultAvatar
            RETURN u
        `;
        const createUserResult = await session.run(createUserQuery, { name, email, password, defaultAvatar });

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
    } finally {
        await session.close();
    }
});

app.get('/dashboard', async (req, res) => {
    const defaultAvatar = '/images/download.png';
    try {
        if (!req.session.user) {
            return res.redirect('/login'); // Redirect if not logged in
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
        if (!req.session.user) return res.redirect('/login');

        const userName = req.session.user.name;

        // Check if the user exists as a Student or Teacher
        const roleCheckQuery = `
            MATCH (u:User {name: $userName})
            OPTIONAL MATCH (u)-[:HAS_ROLE]->(r)
            RETURN r
        `;
        const result = await Session.run(roleCheckQuery, { userName });

        const role = result.records[0].get('r');

        // Fetch profile details based on role (as before)
        const userType = role.labels[0].toLowerCase(); // Assuming labels are Student/Teacher
        req.session.user.role = userType;
        
        res.render('profile', { user: req.session.user });
    } catch (error) {
        console.error('Error checking role:', error);
        res.status(500).send('An error occurred.');
    }
});

// Example for a query inside a route
app.post('/select-role', async (req, res) => {
    const { role } = req.body;
    if (!req.session.user) {
        return res.status(401).send('Unauthorized');
    }

    const session = driver.session(); // Create a new session for this route
    const userName = req.session.user.name;
    const userEmail = req.session.user.email;

    try {
        let createNodeQuery;

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
            return res.status(400).send('Invalid role selected');
        }

        await session.run(createNodeQuery, { userName, userEmail });

        req.session.user.role = role.toLowerCase();
        res.status(200).send('Role set successfully');
    } catch (error) {
        console.error('Error creating role node:', error);
        res.status(500).send('Failed to create role node');
    } finally {
        await session.close(); // Close the session to avoid leaks
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
        req.session.user.role = newRole.toLowerCase();

        // Respond with a success message
        res.status(200).send('Role updated successfully');
    } catch (error) {
        console.error('Error updating role:', error);
        res.status(500).send('Failed to update role');
    }
});

app.get('/mentor', async (req,res) => {
    try {
        if (!req.session.user) return res.redirect('/login');

        res.render('mentor', { user: req.session.user });
    } catch (error) {
        console.error('Error loading mentor:', error);
        res.status(500).send('An error occurred.');
    }
});

app.get('/project', async (req,res) => {
    try {
        if (!req.session.user) return res.redirect('/login');

        res.render('project', { user: req.session.user });
    } catch (error) {
        console.error('Error loading mentor:', error);
        res.status(500).send('An error occurred.');
    }
});

process.on("exit", async () => {
    await driver.close();
});


const PORT = process.env.PORT;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
