const mongoose = require("mongoose");

const Position = require('./position').schema;

const Schema = mongoose.Schema;

const { DateTime } = require("luxon");


const PortfolioSchema = new Schema({
    positions: [
            Position
],
    realizedTot: { type: Number },
    user: { type: Schema.Types.ObjectId, ref: "User" }


}, {timestamps: true, toObject: {virtuals: true}, toJSON: {virtuals: true} });

PortfolioSchema.virtual("createdAt_formatted").get(function () {
    return DateTime.fromJSDate(this.createdAt).toLocaleString(DateTime.DATE_MED);
});

PortfolioSchema.virtual("updatedAt_formatted").get(function () {
    return DateTime.fromJSDate(this.updatedAt).toLocaleString(DateTime.DATE_MED);
});


module.exports = mongoose.model("Portfolio", PortfolioSchema);