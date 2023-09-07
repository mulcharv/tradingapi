const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const WatchlistSchema = new Schema({
    stocks: [String],
    user: { type: Schema.Types.ObjectId, ref: "User" }
});


module.exports = mongoose.model("Watchlist", WatchlistSchema);