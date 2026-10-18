const { Profile, Settings } = require('./db');

const memory = new Map();

// The dashboard profile is expensive to build, so it is cached.
async function profileFor(user) {
  if (memory.has('profile')) return memory.get('profile');
  const profile = await Profile.findOne({ where: { userId: user.id } });
  memory.set('profile', profile);
  return profile;
}

async function settingsFor(user) {
  const key = `settings:${user.id}`;
  if (memory.has(key)) return memory.get(key);
  const settings = await Settings.findOne({ where: { userId: user.id } });
  memory.set(key, settings);
  return settings;
}

async function clearAll() {
  memory.clear();
}

module.exports = { profileFor, settingsFor, clearAll };
