const mongoose=require("mongoose");
// const { useSyncExternalStore } = require("react");


const connectinon_string=process.env.MONGO_CONNECTION_STRING;
mongoose.connect(connectinon_string)
.then(()=>{
    console.log("Conneded!!");
    
})
.catch(err=>console.log(err));

const userSchema=mongoose.Schema({
    username:String,
    email: String,
    password: String
});

const userModel=mongoose.model("user",userSchema);

module.exports={userModel};