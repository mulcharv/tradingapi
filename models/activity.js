const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const ActivitySchema = new Schema({
    actions: [new Schema({
        action: {type: String},
        amount: {type: Number},
        date: {type: String},
    })],
    user: { type: Schema.Types.ObjectId, ref: "User" }
});


module.exports = mongoose.model("Activity", ActivitySchema);