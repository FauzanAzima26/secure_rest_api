let token = "";

const API = "https://secure-api-example.onrender.com";

async function register() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const res = await fetch(`${API}/register`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({username, password})
  });
  document.getElementById("output").textContent = await res.json().then(r => JSON.stringify(r));
}

async function login() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const res = await fetch(`${API}/login`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({username, password})
  });
  const data = await res.json();
  token = data.token;
  document.getElementById("output").textContent = JSON.stringify(data);
}

async function getProtected() {
  const res = await fetch(`${API}/protected`, {
    headers: {"Authorization": `Bearer ${token}`}
  });
  document.getElementById("output").textContent = await res.json().then(r => JSON.stringify(r));
}
