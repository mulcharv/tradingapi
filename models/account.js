const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const { DateTime } = require("luxon");


const AccountSchema = new Schema({
    balance: { type: Number, required: true, min: 0},
    user: { type: Schema.Types.ObjectId, ref: "User" }
}, {timestamps: true, toObject: {virtuals: true}, toJSON: {virtuals: true} });

AccountSchema.virtual("createdAt_formatted").get(function () {
    return DateTime.fromJSDate(this.createdAt).toLocaleString(DateTime.DATE_MED);
});

AccountSchema.virtual("updatedAt_formatted").get(function () {
    return DateTime.fromJSDate(this.updatedAt).toLocaleString(DateTime.DATE_MED);
});


module.exports = mongoose.model("Account", AccountSchema);