const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const PositionSchema = new Schema({
    ticker: { type: String, required: true},
    quantity: { type: Number, required: true, min: 1},
    value: { type: Number, required: true, min: 0},
    realized: { type: Number},
    user: { type: Schema.Types.ObjectId, ref: "User" }
});


module.exports = mongoose.model("Position", PositionSchema);