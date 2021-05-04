const registerValidator = (user) => {
  const { name, email, password, password2 } = user;
  let errors = [];

  if (!name || !email || !password || !password2) {
    errors.push({
      message: "Please enter all fields",
    });
  }

  if (password.length < 6) {
    errors.push({
      message: "Password should be at least 6 characters",
    });
  }

  if (password != password2) {
    errors.push({
      message: "Password do not match",
    });
  }

  return errors;
};

module.exports = {
  registerValidator,
};
