const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const PortfolioSchema = new Schema({
    positions: [
            {
            ticker: String,
            quantity: Number,
            value: Number,
            realized: Number
        }
    ],
    realizedTot: { type: Number },
    user: { type: Schema.Types.ObjectId, ref: "User" }


});


module.exports = mongoose.model("Portfolio", PortfolioSchema);