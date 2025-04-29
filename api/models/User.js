import mongoose from 'mongoose'; // Use import

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, min: 4, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

export default User; // Use export default