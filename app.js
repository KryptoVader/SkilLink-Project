import fetch from "node-fetch"  
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

dotenv.config();

const app = express()
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const driver = neo4j.driver(
    process.env.NEO4J_URI,
    neo4j.auth.basic(process.env.NEO4J_USERNAME,process.env.NEO4J_PASSWORD)
);
const Session = driver.session();

app.set('view engine', 'ejs');
app.use(express.static('Public'));
app.set('views', path.join(__dirname,'Public' ,'views'));
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
                };

                const result = await Session.run(
                    `MERGE (u:User {user_id: $googleId}) 
                     SET u.email = $email, u.name = $name 
                     RETURN u`,
                    user
                );

                // Retrieve stored user data
                const storedUser = result.records[0].get('u').properties;

                // Pass the user object to Passport
                return done(null, storedUser); // Send stored user to serializeUser
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

app.get('/login', (req,res) => {
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

app.get('/auth/google/signin', passport.authenticate('google', {scope: ["profile", "email"]}));

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
        // Check if a user already exists
        const existingUserQuery = `
            MATCH (u:User {name: $name})
            RETURN u
        `;
        const existingUserResult = await Session.run(existingUserQuery, { name});

        if (existingUserResult.records.length > 0) {
            // If user exists, set the session and redirect
            req.session.user = { name, password };
            res.redirect('/dashboard');
        } else {
            // Optionally handle the case where the user does not exist
            return res.status(404).json({ success: false, message: 'User not found' });
        }
    } catch (error) {
        console.error('Error interacting with Neo4j:', error);
        return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

app.post('/add-user', async (req, res) => {
    console.log(req.body); // Log request body to inspect data
    const { name, email, password } = req.body;
    try {
        // Check if the user already exists
        const existingUserQuery = `
            MATCH (u:User {email: $email})
            RETURN u
        `;
        const existingUserResult = await Session.run(existingUserQuery, { email });

        if (existingUserResult.records.length > 0) {
            return res.status(400).send('User already exists with this email');
        }

        // Create a new user node
        const createUserQuery = `
            MERGE (u:User {name: $name, email: $email, password: $password})
            RETURN u
        `;
        const createUserResult = await Session.run(createUserQuery, { name, email, password });

        // Extract the created user's properties
        const createdUser = createUserResult.records[0].get('u').properties;

        // Set session for the user
        req.session.user = {
            name: createdUser.name,
            email: createdUser.email
        };

        res.redirect('/dashboard');

    } catch (error) {
        console.error('Error adding user:', error);
        res.status(500).send('Error adding user: ' + error.message);
    }
});

app.get('/dashboard', async (req, res) => {
    try {
        if (!req.session.user) {
            return res.redirect('/'); // Redirect if user is not logged in
        }

        const recommendations = [
            { name: 'Dr. John Doe', link: '/mentors/suggestion1', description: 'AI Research' },
            { name: 'Deep Learning Project Ideas', link: '/projects/suggestion2', description: 'Collaboration' }
        ];

        res.render('dashboard', {
            user: req.session.user, // Pass user information
            content: '<p>Your current projects and updates can go here.</p>',
            recommendations
        });
    } catch (error) {
        console.error('Error rendering dashboard:', error);
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
