const express = require("express");
const mysqli = require("mysql");
const encrypt = require("bcrypt");
const app = express();
const port = process.env.PORT || 3000;
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const cors = require("cors");

app.use(cors());

dotenv.config();
app.use(express.json());

app.listen(port, () =>{
    console.log(`Server is running on pert: ${port}`);
});

const connection = mysqli.createConnection({
    host: "mysql.railway.internal",
    user: "root",
    password: "UhprMwapBBOKrtYicNHthTHXvLodbgMD",
    database: "railway"
});

connection.connect((err) => {
    if (!err) {
        console.log("Database connected successfully");
    }else{
        console.log("Database connection failed: " + err.message);
    }
});

var tokens = [];

app.post("/user", async (req, res) => {
    const data = req.body;
    if (data && Object.keys(data).length > 0) {
       const hashedPassword = await encrypt.hash(data.password,10);

        connection.query("INSERT INTO users (email,password,name,age) VALUES ('"+data.email+"','"+hashedPassword+"','"+data.name+"','"+data.age+"')", 
            (err, results) => {
            if (err) {
                res.status(500).json({ error: "Database insertion failed: " + err.message });
                return;
            }
            res.status(201).json({ message: "User added successfully", userId: results.insertId, data: data });
        });

        return;
    }else{
        res.status(400).json({ error: "Request body cannot be empty" });
    }
});


app.delete("/user/:id", (req, res) =>{
    const id = req.params.id;
    try {
        connection.query("DELETE FROM users WHERE id='"+id+"'", (err, results) => {
        if (!err){
            res.status(200).json({message: "user is deleted successfully" });
        }else{
            res.status(500).json({ error: "Database deletion failed: " + err.message });
        }
    });
    } catch (error) {
        res.status(500).json({ error: "Database deletion failed: " + error.message });
    }
});


app.get("/user/:id", (req, res) => {
    const userId = req.params.id;

    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        res.status(401).json({ error: "No token provided" });
        return;
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        res.status(401).json({ error: "Invalid token format" });
        return;
    }

    try {
        jwt.verify(token, process.env.SCRET_KEY);
        connection.query("SELECT * FROM users WHERE id = ?", [userId], (err, results) => {
            if (!err) {
                if (results.length > 0) {
                    res.status(200).json({message: "User retrieved successfully", users: results });
                } else {
                    res.status(404).json({message: "User not found", users: [] });
                }
            } else {
                res.status(500).json({ error: "Database query failed: " + err.message });
            }
        }); 
    } catch (error) {
        res.status(401).json({ error: "Invalid token", errorDetails: error.message });
    }
    
    
})

app.put("/user/:id", (req, res) => {
    const {name , age} = req.body;
    const id = req.params.id;
    connection.query("UPDATE users SET name='"+name+"', age='"+age+"' WHERE id='"+id+"'", (err, results) => {
        if (!err) {
            res.status(200).json({message: "user is updated successfully" });
        }else{
            res.status(500).json({ error: "Database update failed: " + err.message });
        }
    });
});


function jwtGenetrator({userid, email}) {
    const JWT_SCRETE = process.env.SCRET_KEY;
    const TOKEN_TIMEOUT = Number(process.env.TOKEN_TIMEOUT);
    const payload = {
        user: userid,
        email: email,
        permision: ["post", "delete"]
    };
    return jwt.sign(payload, JWT_SCRETE, {expiresIn: TOKEN_TIMEOUT});
    
}

app.get("/login", async (req, res) => {
    const {email, password} = req.body;
    try {
        connection.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
            if (!err) {
                if (results.length > 0) {
                    const match = encrypt.compareSync(password, results[0].password);
                    if (match) {
                        const token = jwtGenetrator({userid: results[0].id, email: results[0].email});
                        tokens.push({token: token, user: results[0].id});
                        res.status(200).json({message: "user is authenticated successfully", user: results[0], token: token });
                        return;
                    }
                }
                res.status(401).json({message: "authentication failed!"});
            } else {
                res.status(500).json({ error: "Database query failed: " + err.message });
            }
        });
    } catch (error) {
        res.status(500).json({ error: "Database query failed: " + error.message });
    }
});


app.post("/post", (req,res) => {
    const {title, subtitle} = req.body;
    const header = req.headers['authorization'];
    if (!header) {
        res.status(401).json({ error: "No token provided" });
        return;
    }

    const token = header.split(' ')[1];
    try {
       const user = jwt.verify(token,process.env.SCRET_KEY);
       const permision = user.permision;
       if (user.permision && permision[0] == "post") {
        const userid = user.user;
        connection.query("INSERT INTO post (title, subtitle,userid) VALUES ('"+title+"','"+subtitle+"', '"+userid+"')", (err, results) => {
            if (err) {
                res.status(500).json({ error: err.message });
            }});
            res.status(201).json({ message: "Post created successfully", post: { title, subtitle, userid } });
            } else{
                res.status(403).json({ error: "Insufficient permissions to create a post" });
            }   
    } catch (error) {
        res.status(401).json({ error: "Invalid token", errorDetails: error.message });
    }
});

app.get("/post", (req, res) => {
   const header = req.headers['authorization'];
   if (!header) {
       res.status(401).json({ error: "No token provided" });
       return;
   }
   try {
    const token = header.split(' ')[1];
    const user = jwt.verify(token,process.env.SCRET_KEY);
    const permision = user.permision;
    if (user.permision && permision[0] == "post") {
        connection.query("SELECT * FROM post WHERE userid = ?", [user.user], (err, results) => {
            if (!err) {
                res.status(200).json({message: "Posts retrieved successfully", posts: results });
            } else {
                res.status(500).json({ error: "Database query failed: " + err.message });
            }
        });
    }else{
        res.status(403).json({ error: "Insufficient permissions to view posts" });
    }
   } catch (error) {
    res.status(401).json({ error: "Invalid token", errorDetails: error.message });
   }
});

app.get("/refresh",(req,res)=>{
    const header = req.headers['authorization'];
    if (!header) {
        res.status(401).json({ error: "No token provided" });
        return;
    }

    const token = header.split(' ')[1];
    
   try {
    const decoded = jwt.verify(token, process.env.SCRET_KEY);
        res.status(200).json({ message: "Token is not expired!", token: token });
    
   } catch (error) {
    if (error.name !== 'TokenExpiredError') {
        res.status(401).json({ error: "Invalid token", errorDetails: error.message });
        return;
    }
     const JWT_SCRETE = process.env.SCRET_KEY;
    const TOKEN_TIMEOUT = Number(process.env.TOKEN_TIMEOUT);
    const data = jwt.verify(token, JWT_SCRETE, {ignoreExpiration: true});
    const payload = {
        user: data.user,
        email: data.email,
        permision: data.permision
    }

    const newToken = jwt.sign(payload, JWT_SCRETE, {expiresIn: TOKEN_TIMEOUT});
    res.status(200).json({message: "Token refreshed successfully", token: newToken });
   }
});

app.get("/wel/:name/:age", (req, res) => {
    res.send( "<h1>hello "+req.params.name+"</h1> <br>"+
        "<h1>age "+req.params.age+"</h1>"
    );

});
