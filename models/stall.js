const mongoose = require("mongoose");

const stallSchema = mongoose.Schema({
	// Create a Schema constructor ( mongoose.Schema() )
	name: String,
	business: String,
	email: String,
	telephone: String,
	type: String,
	description: String,
	comments: String,
	authority: String,
	status: String,
	pii: String,
	pliDate: Date,
	risk: String,
	pitchNo: String, // Assume we will set -1 to be default (unassigned pitchNo)
	date: Number, // Since we'll be working with Epoch time, we'll use the Number type
	userId: mongoose.Types.ObjectId,
});

module.exports.Stall = mongoose.model("Stall", stallSchema);
