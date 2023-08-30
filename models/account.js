const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const AccountSchema = new Schema({
    balance: { type: Number, required: true, min: 0},
    user: { type: Schema.Types.ObjectId, ref: "User" }
});


module.exports = mongoose.model("Account", AccountSchema);