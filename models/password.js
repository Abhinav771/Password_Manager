const mongoose=require("mongoose");

const passwordSchema=mongoose.Schema({
    userId:{
        type:mongoose.Schema.Types.ObjectId,
        ref: "users",
        required: true
    },
    website:String,
    username: String,

    password: String,
    iv: String
});

const passwordModel=mongoose.model("password",passwordSchema);

module.exports={passwordModel};

