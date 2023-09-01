const mongoose = require("mongoose");

const Position = require('./position').schema;

const Schema = mongoose.Schema;

const PortfolioSchema = new Schema({
    positions: [
            Position
],
    realizedTot: { type: Number },
    user: { type: Schema.Types.ObjectId, ref: "User" }


});


module.exports = mongoose.model("Portfolio", PortfolioSchema);