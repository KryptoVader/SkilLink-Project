import express from "express";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import path from "path";
import session from "express-session";
import cookieParser from "cookie-parser";
import { fileURLToPath } from "url";
import neo4j from "neo4j-driver";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import multer from "multer";
import axios from 'axios';
import { Server } from "socket.io";
import { createServer } from 'http';

//Add the changes like saving the email and things to session when using /user and etc.
dotenv.config();
const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const driver = neo4j.driver(
    process.env.NEO4J_URI,
    neo4j.auth.basic(process.env.NEO4J_USERNAME, process.env.NEO4J_PASSWORD),
);
const upload = multer({ dest: "uploads/" });
const httpServer = createServer(app);
const io = new Server(httpServer);
const onlineUsers = new Map();

app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "Public")));
app.use(express.json());
app.set("views", path.join(__dirname, "Public", "views"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
}));

app.use(passport.initialize());
app.use(passport.session());

const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
const redirectUri = "http://localhost:3000/auth/google/callback";

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
                    avatarUrl: profile.photos[0]?.value || '/images/download.png',
                    bannerUrl: null,  // Default to null if not set
                };

                // Save or update the user in the database, including the access token
                const result = await session.run(
                    `
                    MERGE (u:User {googleId: $googleId}) 
                    ON CREATE SET u.email = $email, u.name = $name, u.avatarUrl = $avatarUrl, u.bannerUrl = $bannerUrl
                    ON MATCH SET u.avatarUrl = $avatarUrl, u.bannerUrl = $bannerUrl
                    RETURN u
                    `,
                    user
                );

                const storedUser = result.records[0].get('u').properties;

                // Pass the stored user to the next middleware
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
    // Store the googleId instead of user_id
    done(null, user.googleId);
});

passport.deserializeUser(async (googleId, done) => {
    const session = driver.session();
    try {
        const result = await session.run(
            `MATCH (u:User {googleId: $googleId}) RETURN u`,
            { googleId },
        );

        if (result.records.length === 0) {
            return done(new Error("User not found"), null);
        }

        const user = result.records[0].get("u").properties;
        done(null, user);
    } catch (error) {
        done(error, null);
    } finally {
        await session.close();
    }
});

app.get("/", (req, res) => {
    res.render("index");
});

app.get("/login", (req, res) => {
    res.render("signup", { googleClientId });
});

app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Session destruction error:", err);
        }
        res.redirect('/');  // Redirect to Google OAuth login
    });
});

app.get(
    "/auth/google/signin",
    passport.authenticate("google", { scope: ["profile", "email"] }),
);

app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login" }),
    async (req, res) => {
        const session = driver.session();
        try {
            const email = req.user.email; // From deserializeUser
            const roleQuery = `
                MATCH (u:User {email: $email})
                OPTIONAL MATCH (u)-[:HAS_ROLE]->(role)
                RETURN role
            `;
            const result = await session.run(roleQuery, { email });

            const role = result.records[0]?.get("role");

            if (role) {
                req.session.user = {
                    ...req.user,
                    role: role.labels[0].toLowerCase(),
                };
            } else {
                req.session.user = req.user;
            }
            return res.redirect("/dashboard");
        } catch (error) {
            console.error("Error checking user role:", error);
            res.status(500).send("Internal Server Error");
        } finally {
            await session.close();
        }
    },
);

app.post("/user", async (req, res) => {
    const { email, password } = req.body;
    const session = driver.session();

    try {
        const existingUserQuery = `MATCH (u:User {email: $email}) RETURN u`;
        const existingUserResult = await session.run(existingUserQuery, {
            email,
        });

        if (existingUserResult.records.length === 0) {
            return res.status(404).json({
                success: false,
                message: "User not found",
            });
        }

        const user = existingUserResult.records[0].get("u").properties;

        if (user.password !== password) {
            return res.status(401).json({
                success: false,
                message: "Incorrect password",
            });
        }

        const roleCheckQuery = `
            MATCH (u:User {email: $email})
            OPTIONAL MATCH (u)-[:HAS_ROLE]->(r)
            RETURN r
        `;
        const result = await session.run(roleCheckQuery, { email });

        const role = result.records[0]?.get("r");
        const userType = role?.labels[0]?.toLowerCase();

        req.session.user = {
            email: user.email,
            name: user.name,
            avatarUrl: user.avatarUrl || "/images/download.png",
            bannerUrl: user.bannerUrl || null,
            role: userType || null,
        };
        res.redirect("/dashboard");
    } catch (error) {
        console.error("Error interacting with Neo4j:", error);
        res.status(500).json({
            success: false,
            message: "Internal Server Error",
        });
    } finally {
        await session.close();
    }
});

app.post("/add-user", async (req, res) => {
    const { name, email, password } = req.body;
    const defaultAvatar = "/images/download.png";
    const session = driver.session();

    try {
        const existingUserQuery = `MATCH (u:User {email: $email}) RETURN u`;
        const existingUserResult = await session.run(existingUserQuery, {
            email,
        });

        if (existingUserResult.records.length > 0) {
            return res.status(400).send("User already exists with this email");
        }

        const createUserQuery = `
            MERGE (u:User {email: $email, name: $name, password: $password})
            SET u.avatarUrl = $defaultAvatar, u.BannerUrl = null
            RETURN u
        `;
        const createUserResult = await session.run(createUserQuery, {
            name,
            email,
            password,
            defaultAvatar,
        });

        const createdUser = createUserResult.records[0].get("u").properties;

        req.session.user = {
            email: createdUser.email,
            name: createdUser.name,
            avatarUrl: createdUser.avatarUrl,
            bannerUrl: createdUser.bannerUrl || null,
        };

        res.redirect("/dashboard");
    } catch (error) {
        console.error("Error adding user:", error);
        res.status(500).send("Error adding user: " + error.message);
    } finally {
        await session.close();
    }
});

app.get("/dashboard", async (req, res) => {
    const session = driver.session();
    try {
        if (!req.session.user) {
            return res.redirect("/login"); // Redirect if not logged in
        }

        const userEmail = req.session.user.email;

        // Fetch friend requests
        const friendRequestsResult = await session.run(`
            MATCH (u:User {email: $userEmail})<-[:FRIEND_REQUEST {status: "PENDING"}]-(requester:User)
            RETURN requester.email AS email, requester.name AS name, requester.avatarUrl AS avatarUrl
        `, { userEmail });

        const friendRequests = friendRequestsResult.records.map(record => ({
            email: record.get("email"),
            name: record.get("name"),
            avatarUrl: record.get("avatarUrl") || "/images/download.png",
        }));

        // Fetch friends list
        const friendsResult = await session.run(`
    MATCH (u1:User {email: $userEmail})-[:FRIEND_WITH]-(friend:User)
    RETURN friend.email AS email, friend.name AS name, friend.avatarUrl AS avatarUrl, friend.lastSeen AS lastSeen
`, { userEmail });

        const friends = friendsResult.records.map(record => {
            const email = record.get("email");
            const lastSeenRaw = record.get("lastSeen"); // Can be null or undefined

            console.log("Raw lastSeen value:", lastSeenRaw);

            // Fallback for lastSeen
            const lastSeen = lastSeenRaw
                ? new Date(lastSeenRaw).toLocaleString()
                : "Never"; // Fallback if null or invalid

            return {
                email,
                name: record.get("name"),
                avatarUrl: record.get("avatarUrl") || "/images/download.png",
                online: onlineUsers.has(email),
                lastSeen, // Use formatted or fallback value
            };
        });

        // Fetch all groups where the user is OWNER or MEMBER
        const groupsResult = await session.run(
            `
            MATCH (u:User {email: $userEmail})-[:OWNER_OF|MEMBER_OF]->(g:Group)
            RETURN DISTINCT g.name AS name, g.avatarUrl AS iconUrl, g.id AS id
            `,
            { userEmail }
        );

        // Map groups to an array
        const groups = groupsResult.records.map(record => ({
            id: record.get("id"),
            name: record.get("name"),
            iconUrl: record.get("iconUrl") || "/images/default-group.jpeg", // Default icon
        }));
        
        // Render the dashboard
        res.render("dashboard", {
            user: req.session.user,
            friendRequests,
            friends,
            groups,
            selectedFriend: null,
        });
    } catch (error) {
        console.error("Error rendering dashboard:", error);
        res.status(500).send("An error occurred.");
    } finally {
        await session.close();
    }
});

app.get("/profile", async (req, res) => {
    if (!req.session.user) {
        return res.redirect("/login");
    }

    const userEmail = req.session.user.email;
    const session = driver.session();

    try {
        // Query to check if the user has a Student or Teacher role
        const roleCheckQuery = `
            MATCH (u:User {email: $userEmail})-[:HAS_ROLE]->(role)
            OPTIONAL MATCH (role:Student)
            OPTIONAL MATCH (role:Teacher)
            RETURN u, role, 
                   role:Student AS isStudent, 
                   role:Teacher AS isTeacher, 
                   properties(role) AS roleProperties
        `;
        const result = await session.run(roleCheckQuery, { userEmail });

        if (result.records.length === 0) {
            return res.status(404).send("User not found");
        }

        const userNode = result.records[0].get("u").properties;
        const roleNode = result.records[0].get("roleProperties") || {};
        const isStudent = result.records[0].get("isStudent");
        const isTeacher = result.records[0].get("isTeacher");

        // Determine role type and construct profile data
        const roleData = isStudent
            ? {
                role: "Student",
                university: roleNode.university || null,
                cgpa: roleNode.cgpa || null,
                skills: roleNode.skills || [],
                fieldOfInterest: roleNode.fieldOfInterest || null, // Add Field of Interest
            }
            : isTeacher
                ? {
                    role: "Teacher",
                    institution: roleNode.institution || null,
                    highestDegree: roleNode.highestDegree || null,
                    researchInterests: roleNode.researchInterests || [],
                }
                : {
                    role: "Unknown",
                };

        // Combine user data and role-specific data
        const user = {
            name: userNode.name,
            email: userNode.email,
            avatarUrl: userNode.avatarUrl || "/images/download.png",
            bannerUrl: userNode.bannerUrl || null,
            ...roleData,
        };

        // Render the profile page with user and role data
        res.render("profile", { user });
    } catch (error) {
        console.error("Error fetching profile data:", error);
        res.status(500).send("An error occurred");
    } finally {
        await session.close();
    }
});

app.post("/select-role", async (req, res) => {
    const { role } = req.body;
    if (!req.session.user) {
        return res.status(401).send("Unauthorized");
    }

    const session = driver.session(); // Create a new session for this route
    const userEmail = req.session.user.email;

    try {
        let createNodeQuery;

        if (role === "Student") {
            // Only create the Student node if it doesn't exist
            createNodeQuery = `
            MATCH (u:User {email: $userEmail})
            MERGE (u)-[:HAS_ROLE]->(s:Student {email: $userEmail})
            ON CREATE SET s.cgpa = null, s.skills = [], s.university = null
            RETURN s
        `;
        } else if (role === "Teacher") {
            // Only create the Teacher node if it doesn't exist
            createNodeQuery = `
            MATCH (u:User {email: $userEmail})
            MERGE (u)-[:HAS_ROLE]->(t:Teacher {email: $userEmail})
            ON CREATE SET t.institution = null, t.highestDegree = null, t.researchInterests = [], t.about = null
            RETURN t
        `;
        } else {
            return res.status(400).send("Invalid role selected");
        }

        const result = await session.run(createNodeQuery, { userEmail });
        const createdNode = result.records[0].get(0).properties;

        // Update the session with the user's new role
        req.session.user.role = role.toLowerCase();
        res.status(200).send("Role set successfully");
    } catch (error) {
        console.error("Error creating role node:", error);
        res.status(500).send("Failed to create role node");
    } finally {
        await session.close(); // Close the session to avoid leaks
    }
});

app.post("/update-role", async (req, res) => {
    const session = driver.session();
    const { newRole } = req.body;

    if (!req.session.user) {
        return res.status(401).send("Unauthorized");
    }

    const userEmail = req.session.user.email;

    try {
        // Step 1: Remove existing role relationship and node
        await session.run(
            `
            MATCH (u:User {email: $userEmail})-[r:HAS_ROLE]->(role)
            DELETE r, role
            `,
            { userEmail }
        );

        // Step 2: Create a new role node
        let createRoleQuery;
        if (newRole === "Student") {
            createRoleQuery = `
                MATCH (u:User {email: $userEmail})
                MERGE (u)-[:HAS_ROLE]->(s:Student {email: $userEmail})
                ON CREATE SET s.cgpa = null, s.skills = [], s.university = null, s.fieldOfInterest = []
                RETURN s
            `;
        } else if (newRole === "Teacher") {
            createRoleQuery = `
                MATCH (u:User {email: $userEmail})
                MERGE (u)-[:HAS_ROLE]->(t:Teacher {email: $userEmail})
                ON CREATE SET t.institution = null, t.highestDegree = null, t.researchInterests = []
                RETURN t
            `;
        } else {
            return res.status(400).send("Invalid role selected");
        }

        await session.run(createRoleQuery, { userEmail });

        // Update session with new role
        req.session.user.role = newRole.toLowerCase();

        res.status(200).send("Role updated successfully");
    } catch (error) {
        console.error("Error updating role:", error);
        res.status(500).send("Failed to update role");
    } finally {
        await session.close();
    }
});

app.get("/mentor", async (req, res) => {
    try {
        if (!req.session.user) return res.redirect("/login");

        res.render("mentor", { user: req.session.user });
    } catch (error) {
        console.error("Error loading mentor:", error);
        res.status(500).send("An error occurred.");
    }
});

app.get("/project", async (req, res) => {
    try {
        if (!req.session.user) return res.redirect("/login");

        res.render("project", { user: req.session.user });
    } catch (error) {
        console.error("Error loading mentor:", error);
        res.status(500).send("An error occurred.");
    }
});

app.get("/search", async (req, res) => {
    const query = req.query.query?.toLowerCase();
    const currentUserEmail = req.user?.email;

    if (!query) {
        return res.status(400).send("Query parameter is required");
    }

    const session = driver.session();
    try {
        const searchQuery = `
            MATCH (u:User)
            WHERE (toLower(u.name) CONTAINS $query)
                  AND u.email <> $currentUserEmail
            RETURN DISTINCT u LIMIT 10
        `;

        const result = await session.run(searchQuery, {
            query,
            currentUserEmail,
        });
        const users = result.records.map((record) => {
            const user = record.get("u").properties;

            return {
                name: user.name,
                email: user.email,
                avatarUrl: user.avatarUrl || "/images/download.png",
                profileUrl: `/profile/${encodeURIComponent(user.email)}`, // Use email as unique identifier
            };
        });

        res.json(users);
    } catch (error) {
        console.error("Error during search:", error);
        res.status(500).send("An error occurred during search");
    } finally {
        await session.close();
    }
});

app.get("/profile/:email", async (req, res) => {
    const userEmail = decodeURIComponent(req.params.email); // Decode email from the URL
    const session = driver.session();

    try {
        const loggedInUserAvatar = req.session.user?.avatarUrl || "/images/download.png";
        // Query to check if the user has a Student or Teacher role
        const roleCheckQuery = `
            MATCH (u:User {email: $email})-[:HAS_ROLE]->(role)
            OPTIONAL MATCH (role:Student)
            OPTIONAL MATCH (role:Teacher)
            RETURN u, role, 
                   role:Student AS isStudent, 
                   role:Teacher AS isTeacher, 
                   properties(role) AS roleProperties
        `;
        const result = await session.run(roleCheckQuery, { email: userEmail });

        if (result.records.length === 0) {
            return res.status(404).send("User not found");
        }

        const userNode = result.records[0].get("u").properties;
        const roleNode = result.records[0].get("roleProperties") || {};
        const isStudent = result.records[0].get("isStudent");
        const isTeacher = result.records[0].get("isTeacher");

        // Determine role type and construct profile data
        const roleData = isStudent
            ? {
                role: "Student",
                university: roleNode.university || null,
                cgpa: roleNode.cgpa || null,
                skills: roleNode.skills || [],
                fieldOfInterest: Array.isArray(roleNode.fieldOfInterest)
                    ? roleNode.fieldOfInterest
                    : roleNode.fieldOfInterest
                        ? roleNode.fieldOfInterest.split(",").map((field) => field.trim())
                        : [], // Ensure fieldOfInterest is an array
            }
            : isTeacher
                ? {
                    role: "Teacher",
                    institution: roleNode.institution || null,
                    highestDegree: roleNode.highestDegree || null,
                    researchInterests: roleNode.researchInterests || [],
                }
                : {
                    role: "Unknown",
                };

        // Combine user data and role-specific data
        const user = {
            name: userNode.name,
            email: userNode.email,
            avatarUrl: userNode.avatarUrl || "/images/default-avatar.png",
            bannerUrl: userNode.bannerUrl || null,
            ...roleData,
        };

        // Render the profile page with user and role data
        res.render("user-profile", { user, loggedInUserAvatar });
    } catch (error) {
        console.error("Error fetching profile data:", error);
        res.status(500).send("An error occurred");
    } finally {
        await session.close();
    }
});

app.post(
    "/profile/update",
    upload.fields([
        { name: "profilePicture", maxCount: 1 },
        { name: "bannerPicture", maxCount: 1 },
    ]),
    async (req, res) => {
        if (!req.session.user) {
            return res.status(401).send("Unauthorized");
        }

        const {
            name,
            headline,
            email,
            phone,
            university,
            cgpa,
            skills,
            fieldOfInterest, // Added fieldOfInterest
            institution,
            highestDegree,
            researchInterests,
        } = req.body;

        const userEmail = req.session.user.email;
        const session = driver.session();

        try {
            // Handle profile and banner pictures
            const avatarUrl = req.files?.profilePicture
                ? `/uploads/${req.files.profilePicture[0].filename}`
                : req.session.user.avatarUrl;
            const bannerUrl = req.files?.bannerPicture
                ? `/uploads/${req.files.bannerPicture[0].filename}`
                : req.session.user.bannerUrl;

            const updates = {
                name,
                headline,
                email,
                phone,
                avatarUrl,
                bannerUrl, // Include the bannerUrl in updates
            };

            // Step 1: Update user data in the User node
            await session.run(
                `
                MATCH (u:User {email: $userEmail})
                SET u += $updates
                `,
                { userEmail, updates }
            );

            // Update the session with the new user data
            req.session.user = { ...req.session.user, ...updates };

            // Step 2: Load current role data (Student or Teacher)
            const role = req.session.user.role;
            let existingRoleData = {};

            if (role === "student") {
                // Fetch existing Student data
                const result = await session.run(
                    `
                    MATCH (u:User {email: $userEmail})-[:HAS_ROLE]->(s:Student)
                    RETURN s
                    `,
                    { userEmail }
                );

                if (result.records.length > 0) {
                    existingRoleData = result.records[0].get("s").properties;
                }
            } else if (role === "teacher") {
                // Fetch existing Teacher data
                const result = await session.run(
                    `
                    MATCH (u:User {email: $userEmail})-[:HAS_ROLE]->(t:Teacher)
                    RETURN t
                    `,
                    { userEmail }
                );

                if (result.records.length > 0) {
                    existingRoleData = result.records[0].get("t").properties;
                }
            }

            // Step 3: Role-specific updates (only update the changed fields)
            let roleUpdates = {};

            if (role === "student") {
                roleUpdates = {
                    university: university || existingRoleData.university || null,
                    cgpa: cgpa || existingRoleData.cgpa || null,
                    skills: skills ? skills.split(",").map((skill) => skill.trim()) : existingRoleData.skills || [],
                    fieldOfInterest: fieldOfInterest || existingRoleData.fieldOfInterest || null, // Include fieldOfInterest
                };

                // Delete the old Student node if it exists
                await session.run(
                    `
                    MATCH (u:User {email: $userEmail})-[r:HAS_ROLE]->(s:Student)
                    DELETE r, s
                    `,
                    { userEmail }
                );

                // Create a new Student node
                await session.run(
                    `
                    MATCH (u:User {email: $userEmail})
                    MERGE (u)-[:HAS_ROLE]->(s:Student {email: $userEmail})
                    SET s += $roleUpdates
                    `,
                    { userEmail, roleUpdates }
                );
            } else if (role === "teacher") {
                roleUpdates = {
                    institution: institution || existingRoleData.institution || null,
                    highestDegree: highestDegree || existingRoleData.highestDegree || null,
                    researchInterests: researchInterests
                        ? researchInterests.split(",").map((interest) => interest.trim())
                        : existingRoleData.researchInterests || [],
                };

                // Delete the old Teacher node if it exists
                await session.run(
                    `
                    MATCH (u:User {email: $userEmail})-[r:HAS_ROLE]->(t:Teacher)
                    DELETE r, t
                    `,
                    { userEmail }
                );

                // Create a new Teacher node
                await session.run(
                    `
                    MATCH (u:User {email: $userEmail})
                    MERGE (u)-[:HAS_ROLE]->(t:Teacher {email: $userEmail})
                    SET t += $roleUpdates
                    `,
                    { userEmail, roleUpdates }
                );
            }

            // Step 4: Final session update and response
            req.session.user = { ...req.session.user, role: role.toLowerCase() };
            res.redirect("/profile");
        } catch (error) {
            console.error("Error updating profile:", error);
            res.status(500).send("Failed to update profile");
        } finally {
            await session.close(); // Close the session to avoid memory leaks
        }
    }
);

app.post("/connect", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const { targetEmail } = req.body;
    const currentUserEmail = req.session.user.email;
    const session = driver.session();

    try {
        const result = await session.run(
            `
            MATCH (u1:User {email: $currentUserEmail}), (u2:User {email: $targetEmail})
            MERGE (u1)-[r:FRIEND_REQUEST]->(u2)
            ON CREATE SET r.status = "PENDING", r.timestamp = timestamp()
            RETURN r
            `,
            { currentUserEmail, targetEmail }
        );

        if (result.records.length > 0) {
            res.status(200).json({ success: true, message: "Connection request sent." });
        } else {
            res.status(400).json({ success: false, message: "Failed to send connection request." });
        }
    } catch (error) {
        console.error("Error sending connect request:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    } finally {
        await session.close();
    }
});

app.get("/friend-requests", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const userEmail = req.session.user.email;
    const session = driver.session();

    try {
        const result = await session.run(
            `
            MATCH (u:User {email: $userEmail})<-[:FRIEND_REQUEST {status: "PENDING"}]-(requester:User)
            RETURN requester.email AS email, requester.name AS name, requester.avatarUrl AS avatarUrl
            `,
            { userEmail }
        );

        const requests = result.records.map(record => ({
            email: record.get("email"),
            name: record.get("name"),
            avatarUrl: record.get("avatarUrl") || "/images/default-avatar.png",
        }));

        res.json(requests);
    } catch (error) {
        console.error("Error fetching friend requests:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    } finally {
        await session.close();
    }
});

app.post("/handle-request", async (req, res) => {
    if (!req.session.user) {
        return res.redirect("/login");
    }

    const { requesterEmail, action } = req.body;
    const currentUserEmail = req.session.user.email;
    const session = driver.session();

    try {
        if (action === "ACCEPT") {
            await session.run(`
                MATCH (u1:User {email: $currentUserEmail})<-[r:FRIEND_REQUEST {status: "PENDING"}]-(u2:User {email: $requesterEmail})
                MERGE (u1)-[:FRIEND_WITH]-(u2)
                DELETE r
            `, { currentUserEmail, requesterEmail });
        } else if (action === "REJECT") {
            await session.run(
                `
                MATCH (u1:User {email: $currentUserEmail})<-[r:FRIEND_REQUEST {status: "PENDING"}]-(u2:User {email: $requesterEmail})
                DELETE r
                `,
                { currentUserEmail, requesterEmail }
            );
        }

        res.json({ success: true, message: `Request ${action.toLowerCase()}ed successfully.` });
    } catch (error) {
        console.error("Error handling friend request:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    } finally {
        await session.close();
    }
});

app.get("/friends", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const userEmail = req.session.user.email;
    const session = driver.session();

    try {
        const result = await session.run(
            `
            MATCH (u1:User {email: $userEmail})-[:FRIEND_WITH]-(friend:User)
            RETURN friend.email AS email, friend.name AS name, friend.avatarUrl AS avatarUrl
            `,
            { userEmail }
        );

        const friends = result.records.map(record => ({
            email: record.get("email"),
            name: record.get("name"),
            avatarUrl: record.get("avatarUrl") || "/images/default-avatar.png",
        }));

        res.json(friends);
    } catch (error) {
        console.error("Error fetching friends:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    } finally {
        await session.close();
    }
});

app.get("/recommendations-page", (req, res) => {
    if (!req.session.user) {
        return res.redirect("/login"); // Ensure user is logged in
    }
    res.render("recommendations", { user: req.session.user }); // Pass user data to render
});

app.get("/recommendations", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Unauthorized access. Please log in." });
    }

    const session = driver.session();
    const userEmail = req.session.user.email;

    try {
        // Fetch user's role data from Neo4j
        const result = await session.run(
            `
            MATCH (u:User {email: $email})-[:HAS_ROLE]->(role:Student)
            RETURN role.skills AS skills, role.cgpa AS cgpa
            `,
            { email: userEmail }
        );

        if (result.records.length === 0) {
            return res.status(404).json({ success: false, message: "User role data not found." });
        }

        // Extract user data
        const userData = result.records[0].toObject();
        const skills = userData.skills || []; // Default to an empty array if skills are missing
        const cgpa = parseFloat(userData.cgpa);

        // Validate skills and CGPA
        if (!skills.length || isNaN(cgpa)) {
            return res.status(400).json({ success: false, message: "Incomplete user data. Ensure skills and CGPA are set." });
        }

        // Prepare data for the ML service
        const payload = {
            email: userEmail,
            skills: skills.join(", "), // Convert array to string for ML model
            cgpa: cgpa,
            top_n: 5, // Number of recommendations to return
        };

        // Call the ML service
        const mlResponse = await axios.post("http://127.0.0.1:5000/recommendations", payload);

        // Validate ML service response
        if (!mlResponse.data.success) {
            return res.status(500).json({ success: false, message: "Error in ML service: " + mlResponse.data.message });
        }

        // Return recommendations with avatarUrl
        res.status(200).json({
            success: true,
            recommendations: mlResponse.data.recommendations.map(rec => ({
                ...rec,
                avatarUrl: rec.avatarUrl || '/images/download.png'  // Ensure default avatar if missing
            })),
        });
    } catch (error) {
        // Handle errors
        console.error("Error fetching recommendations:", error.message);
        res.status(500).json({
            success: false,
            message: "An error occurred while fetching recommendations. Please try again later.",
            error: error.message,
        });
    } finally {
        await session.close();
    }
});

app.get("/messages/:friendId", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).send("Unauthorized");
    }

    const { friendId } = req.params;
    const userEmail = req.session.user.email; // Assuming user email is in session
    const session = driver.session();

    try {
        // Fetch messages
        const messageResult = await session.run(
            `
            MATCH (sender:User)-[m:MESSAGED]->(recipient:User)
            WHERE (sender.email = $userEmail AND recipient.email = $friendId) OR
                  (sender.email = $friendId AND recipient.email = $userEmail)
            RETURN m.text AS text, m.timestamp AS timestamp,
                   sender.email AS senderEmail, sender.name AS senderName, sender.avatarUrl AS senderAvatar
            ORDER BY m.timestamp ASC
            `,
            { userEmail, friendId }
        );

        const messages = messageResult.records.map(record => ({
            text: record.get("text"),
            timestamp: Number(record.get("timestamp")),
            senderEmail: record.get("senderEmail"),
            senderName: record.get("senderName"),
            senderAvatar: record.get("senderAvatar") || "/images/download.png",
        }));

        // Fetch friend details
        const friendResult = await session.run(`
            MATCH (u:User {email: $friendId})
            RETURN u.email AS email, u.name AS name, u.avatarUrl AS avatarUrl, u.lastSeen AS lastSeen
        `, { friendId });

        const friend = friendResult.records[0]?.toObject() || {
            email: friendId, // Fallback to friendId if no data is found
            name: "Unknown",
            avatarUrl: "/images/download.png",
            lastSeen: "Never",
            online: false // Default offline if not found in onlineUsers
        };

        let lastSeen = friend.lastSeen;
        if (lastSeen && !isNaN(new Date(lastSeen).getTime())) {
            lastSeen = new Date(lastSeen).toLocaleString();
        } else {
            lastSeen = "Never"; // Default fallback
        }

        console.log(`Last Seen in messages: {lastSeen}`, { lastSeen });


        // Set the online status based on the onlineUsers map
        friend.online = onlineUsers.has(friend.email); // Check if the friend is online

        // Add formatted lastSeen to the friend object
        friend.lastSeen = lastSeen;

        const user = req.session.user;

        // Render the messages view
        res.render("partials/messages", { messages, friend, friendId, user });
    } catch (error) {
        console.error("Error fetching messages:", error);
        res.status(500).send("Internal Server Error");
    } finally {
        await session.close();
    }
});

app.post("/send-message", async (req, res) => {
    const { friendId, message } = req.body;
    const userEmail = req.session.user.email;
    const session = driver.session();

    try {
        // Save the message
        await session.run(
            `
            MATCH (sender:User {email: $userEmail}), (recipient:User {email: $friendId})
            CREATE (sender)-[m:MESSAGED {text: $message, timestamp: timestamp()}]->(recipient)
            `,
            { userEmail, friendId, message }
        );

        res.status(200).json({ success: true });
    } catch (error) {
        console.error("Error sending message:", error);
        res.status(500).json({ success: false });
    } finally {
        await session.close();
    }
});

app.post("/remove-friend", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const { friendEmail } = req.body;
    const userEmail = req.session.user.email;
    const session = driver.session();

    try {
        await session.run(
            `
            MATCH (u1:User {email: $userEmail})-[r:FRIEND_WITH]-(u2:User {email: $friendEmail})
            DELETE r
            `,
            { userEmail, friendEmail }
        );

        res.json({ success: true, message: "Friend removed successfully." });
    } catch (error) {
        console.error("Error removing friend:", error);
        res.status(500).json({ success: false, message: "Failed to remove friend." });
    } finally {
        await session.close();
    }
});

//Socket IO Implementation
io.on("connection", (socket) => {
    const userEmail = socket.handshake.query.email;

    // When a user goes online
    socket.on("user-online", async (email) => {
        if (!email) return;

        onlineUsers.set(email, socket.id); // Add user to online map

        // Notify the user's friends about their online status
        const session = driver.session();
        try {
            const friendsResult = await session.run(`
                MATCH (u:User {email: $email})-[:FRIEND_WITH]-(friend:User)
                RETURN friend.email AS friendEmail
            `, { email });

            const friends = friendsResult.records.map(record => record.get("friendEmail"));
            friends.forEach(friendEmail => {
                const friendSocketId = onlineUsers.get(friendEmail);
                if (friendSocketId) {
                    io.to(friendSocketId).emit("friend-status", { email, online: true });
                }
            });
        } catch (error) {
            console.error("Error broadcasting online status:", error);
        } finally {
            await session.close();
        }
    });

    // Handle real-time messaging
    socket.on("send-message", async (data) => {
        const { sender, recipient, text, senderAvatar } = data;

        // Validate message data
        if (!sender || !recipient || !text) return;

        const session = driver.session();
        try {
            // Save the message to the database
            await session.run(`
                MATCH (u1:User {email: $sender}), (u2:User {email: $recipient})
                CREATE (u1)-[:MESSAGED {text: $text, timestamp: timestamp()}]->(u2)
            `, { sender, recipient, text });

            // Send the message to the recipient in real-time if they are online
            const recipientSocketId = onlineUsers.get(recipient);
            if (recipientSocketId) {
                io.to(recipientSocketId).emit("receive-message", {
                    sender,
                    text,
                    timestamp: Date.now(),
                    senderAvatar,
                });
            }

            // Optionally, send the message back to the sender for real-time UI updates
            // If you want the sender to see the message in real-time as well, emit here
            const senderSocketId = onlineUsers.get(sender);
            if (senderSocketId) {
                io.to(senderSocketId).emit("message-sent", {
                    recipient,
                    text,
                    timestamp: Date.now(),
                    senderAvatar,
                });
            }
        } catch (error) {
            console.error("Error handling send-message:", error);
        } finally {
            await session.close();
        }
    });

    // Handle typing notification
    socket.on("typing", (data) => {
        const { sender, recipient } = data;

        if (!sender || !recipient) return;

        const recipientSocketId = onlineUsers.get(recipient);
        if (recipientSocketId) {
            io.to(recipientSocketId).emit("user-typing", {
                sender,
                senderName: data.senderName, // Pass the sender's name for display
            });
        }
    });

    socket.on("disconnect", async () => {
        let disconnectedEmail = null;

        // Find and remove the disconnected user
        for (const [email, socketId] of onlineUsers) {
            if (socketId === socket.id) {
                disconnectedEmail = email;
                onlineUsers.delete(email);
                console.log(`${email} went offline.`);
                break;
            }
        }

        if (!disconnectedEmail) return; // Exit if no user was found

        const session = driver.session();
        try {
            const lastSeen = new Date().toISOString(); // Get current timestamp
            console.log("Updating lastSeen for:", disconnectedEmail, "with time:", lastSeen);

            // Update the user's lastSeen timestamp in the database
            await session.run(
                `
            MATCH (u:User {email: $email})
            SET u.lastSeen = $lastSeen
        `,
                { email: disconnectedEmail, lastSeen }
            );

            // Fetch all friends of the disconnected user
            const friendsResult = await session.run(
                `
            MATCH (u:User {email: $email})-[:FRIEND_WITH]-(friend:User)
            RETURN friend.email AS friendEmail
        `,
                { email: disconnectedEmail }
            );

            const friends = friendsResult.records.map(record => record.get("friendEmail"));

            // Notify online friends about the disconnection
            for (const friendEmail of friends) {
                const friendSocketId = onlineUsers.get(friendEmail);
                if (friendSocketId) {
                    io.to(friendSocketId).emit("friend-status", {
                        email: disconnectedEmail,
                        online: false,
                        lastSeen,
                    });
                }
            }
        } catch (error) {
            console.error("Error handling disconnection:", error);
        } finally {
            await session.close();
        }
    });
});

app.get('/groups', (req, res) => {
    try {
        const user = req.session.user;
        if (!user) {
            return res.redirect('/login')
        }

        res.render('group', { user });

    } catch (error) {
        console.error('Error rendering create group page:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post("/create-group", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).send("Unauthorized. Please log in.");
    }

    // Match field names from the form
    const { "group-name": groupName, "group-category": groupCategory, "group-description": groupDescription, privacy } = req.body;

    const userEmail = req.session.user.email; // Current user's email
    const session = driver.session();

    // Validate inputs
    if (!groupName || !groupCategory || !groupDescription || !privacy) {
        console.error("Missing parameters:", { groupName, groupCategory, groupDescription, privacy });
        return res.status(400).send("Missing required parameters.");
    }

    try {
        // Generate a unique ID for the group
        const groupId = `group-${Date.now()}`;

        console.log("Creating group with parameters:", {
            userEmail,
            groupId,
            groupName,
            groupCategory,
            groupDescription,
            privacy,
        });

        // Create the group and link it to the creator as OWNER and MEMBER
        await session.run(
            `
            MATCH (u:User {email: $userEmail})
            MERGE (g:Group {id: $groupId})
            ON CREATE SET 
                g.name = $groupName,
                g.category = $groupCategory,
                g.description = $groupDescription,
                g.privacy = $privacy,
                g.avatarUrl = '/images/default-group.jpeg',
                g.createdAt = timestamp()
            MERGE (u)-[:OWNER_OF]->(g)
            MERGE (u)-[:MEMBER_OF]->(g)
            `,
            {
                userEmail,
                groupId,
                groupName,
                groupCategory,
                groupDescription,
                privacy,
            }
        );

        res.redirect("/dashboard"); // Redirect to the dashboard after creation
    } catch (error) {
        console.error("Error creating group:", error);
        res.status(500).send("Failed to create group.");
    } finally {
        await session.close();
    }
});

app.post("/group/:id/invite", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).send("Unauthorized. Please log in.");
    }

    const groupId = req.params.id; // Group ID from the URL
    const { collaboratorEmail } = req.body; // Email of the invited collaborator
    const userEmail = req.session.user.email; // Current user's email
    const session = driver.session();

    try {
        // Check if the user is the owner of the group
        const ownerResult = await session.run(
            `
            MATCH (u:User {email: $userEmail})-[:OWNER_OF]->(g:Group {id: $groupId})
            RETURN g
            `,
            { userEmail, groupId }
        );

        if (ownerResult.records.length === 0) {
            return res.status(403).send("You are not the owner of this group.");
        }

        // Send an invitation to the collaborator
        await session.run(
            `
            MATCH (g:Group {id: $groupId}), (u:User {email: $collaboratorEmail})
            MERGE (u)-[:INVITED_TO]->(g)
            `,
            { groupId, collaboratorEmail }
        );

        res.status(200).send("Invitation sent successfully.");
    } catch (error) {
        console.error("Error sending invite:", error);
        res.status(500).send("Failed to send invite.");
    } finally {
        await session.close();
    }
});

app.post("/group/:id/join", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).send("Unauthorized. Please log in.");
    }

    const groupId = req.params.id; // Group ID
    const userEmail = req.session.user.email; // Collaborator's email
    const session = driver.session();

    try {
        // Check group privacy settings
        const groupResult = await session.run(
            `
            MATCH (g:Group {id: $groupId})
            RETURN g.privacy AS privacy
            `,
            { groupId }
        );

        if (groupResult.records.length === 0) {
            return res.status(404).send("Group not found.");
        }

        const privacy = groupResult.records[0].get("privacy");

        if (privacy === "public") {
            // Directly join the group
            await session.run(
                `
                MATCH (u:User {email: $userEmail}), (g:Group {id: $groupId})
                MERGE (u)-[:MEMBER_OF]->(g)
                `,
                { userEmail, groupId }
            );

            return res.status(200).send("Successfully joined the group.");
        } else {
            // Send a join request for private groups
            await session.run(
                `
                MATCH (u:User {email: $userEmail}), (g:Group {id: $groupId})
                MERGE (u)-[:REQUESTED_TO_JOIN]->(g)
                `,
                { userEmail, groupId }
            );

            return res.status(200).send("Join request sent. Awaiting approval.");
        }
    } catch (error) {
        console.error("Error joining group:", error);
        res.status(500).send("Failed to join group.");
    } finally {
        await session.close();
    }
});

app.post("/group/:id/handle-request", async (req, res) => {
    if (!req.session.user) {
        return res.status(401).send("Unauthorized. Please log in.");
    }

    const { collaboratorEmail, action } = req.body; // 'accept' or 'reject'
    const groupId = req.params.id;
    const userEmail = req.session.user.email;
    const session = driver.session();

    try {
        // Check if the user is the owner of the group
        const ownerResult = await session.run(
            `
            MATCH (u:User {email: $userEmail})-[:OWNER_OF]->(g:Group {id: $groupId})
            RETURN g
            `,
            { userEmail, groupId }
        );

        if (ownerResult.records.length === 0) {
            return res.status(403).send("You are not the owner of this group.");
        }

        if (action === "accept") {
            // Accept the request: Add the user as a MEMBER and remove the REQUESTED_TO_JOIN relationship
            await session.run(
                `
                MATCH (u:User {email: $collaboratorEmail})-[r:REQUESTED_TO_JOIN]->(g:Group {id: $groupId})
                MERGE (u)-[:MEMBER_OF]->(g)
                DELETE r
                `,
                { collaboratorEmail, groupId }
            );

            return res.status(200).send("Request accepted successfully.");
        } else if (action === "reject") {
            // Reject the request: Remove the REQUESTED_TO_JOIN relationship
            await session.run(
                `
                MATCH (u:User {email: $collaboratorEmail})-[r:REQUESTED_TO_JOIN]->(g:Group {id: $groupId})
                DELETE r
                `,
                { collaboratorEmail, groupId }
            );

            return res.status(200).send("Request rejected successfully.");
        } else {
            return res.status(400).send("Invalid action.");
        }
    } catch (error) {
        console.error("Error handling join request:", error);
        res.status(500).send("Failed to handle join request.");
    } finally {
        await session.close();
    }
});

process.on("exit", async () => {
    await driver.close();
});

const PORT = process.env.PORT;
httpServer.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
