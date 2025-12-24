const jwt=require("jsonwebtoken");
const express=require("express");
const cookieParser = require("cookie-parser");
const path=require("path");
const cors = require("cors");
require("dotenv").config();
const app=express();
const bcrypt=require("bcrypt");
const {userModel}=require("./models/users");
const {passwordModel}=require("./models/password");
const crypto = require("crypto");


app.use(express.json());
app.use(cors());
app.use(cookieParser());


function encrypt(text) {
    const iv = crypto.randomBytes(16); // Generate random Initialization Vector
    const cipher = crypto.createCipheriv(process.env.ALGORITHM, Buffer.from(process.env.CRYPTO_SECRET_KEY), iv);
    
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    return { 
        iv: iv.toString('hex'), 
        encryptedData: encrypted.toString('hex') 
    };
}


function decrypt(encryption) {
   
    const decipher = crypto.createDecipheriv(
        process.env.ALGORITHM, 
        Buffer.from(process.env.CRYPTO_SECRET_KEY), 
        Buffer.from(encryption.iv, 'hex')
    );

    let decrypted = decipher.update(Buffer.from(encryption.password, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString();
}


app.get("/",function(req,res){
    res.sendFile(path.join(__dirname,"views","index.html"));
})

app.post("/signup",async function(req,res){
    const username=req.body.username;
    const email=req.body.email;
    const password=req.body.password;

    const newPass=await bcrypt.hash(password, 10);
    
    try {
        await userModel.create({
            username: username,
            email: email,
            password: newPass
        });
        console.log(newPass);
        res.json({ message: "User created successfully" });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Error creating user" });
    }

})


app.post("/login",async function(req,res){
    const username=req.body.username;
    const password=req.body.password;
    try{
        const user=await userModel.findOne({username: username});
        if (!user) {
                
                return res.status(400).json({ message: "Invalid credentials (User not found)" });
            }
        const hashPass=user.password;
        const isCorrect=await bcrypt.compare(password, hashPass);
        if(isCorrect){
            console.log(user);
            const token = jwt.sign({
                    id: user._id
                }, process.env.JWT_SECRET);

               res.cookie("token", token, {
                    httpOnly: true, // Prevents JS from reading the cookie (Security)
                    secure: false,  // Set to true if using HTTPS (Production)
                    maxAge: 3600000 // Cookie expires in 1 hour (in milliseconds)
                });
                res.json({
                    message: "User logged in successfully"
                });
        }
        else{
            res.status(400).json({ message: "Invalid credentials (Wrong Pass)" });
        }

    }
    catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
    
    
})

app.get("/dashboard",function(req,res){
    res.sendFile(path.join(__dirname,"views","dashboard.html"));
})

app.post("/add-password",async function(req,res){
    const token= req.cookies.token;
    if(!token){
        return res.status(401).json({ message: "No session found. Please login." });
    }

    let userId;
    try{
        const decoded=jwt.verify(token,process.env.JWT_SECRET);
        userId=decoded.id;
    } catch (err) {
        
        return res.status(401).json({ message: "Invalid Token" });
    }
    const { website, username, password } = req.body;
    try {
      
        const { iv, encryptedData } = encrypt(password);

       
        await passwordModel.create({
            userId: userId, 
            website: website,
            username: username,
            password: encryptedData, 
            iv: iv
        });

        res.json({ message: "Password saved securely!" });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Error saving password" });
    }
})


app.get("/get-passwords", async function(req, res) {
   
    const token =req.cookies.token; 

    if (!token) {
        return res.status(401).json({ message: "No session found." });
    }

    let userId;
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        userId = decoded.id;
    } catch (err) {
        return res.status(401).json({ message: "Invalid Token" });
    }

    try {
        
        const passwords = await passwordModel.find({ userId: userId });

       
        const decryptedList = passwords.map(item => {
            return {
                _id: item._id,
                website: item.website,
                username: item.username,
                
                password: decrypt({ 
                    password: item.password, 
                    iv: item.iv 
                }) 
            };
        });

        res.json(decryptedList);

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Error fetching passwords" });
    }
});

app.post("/delete-password", async function(req, res) {
   
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "No session found." });

    let userId;
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        userId = decoded.id;
    } catch (err) {
        return res.status(401).json({ message: "Invalid Token" });
    }

    
    const { id } = req.body; 

    try {
       
        const result = await passwordModel.findOneAndDelete({ 
            _id: id, 
            userId: userId 
        });

        if (result) {
            res.json({ message: "Password deleted successfully" });
        } else {
            res.status(404).json({ message: "Password not found or not authorized" });
        }

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Error deleting password" });
    }
});

app.get("/logout", (req, res) => {
    res.clearCookie("token");
    res.redirect("/");
});

app.listen(3000);
