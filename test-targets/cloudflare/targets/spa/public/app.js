/**
 * SPA client runtime logic.
 * Dynamically calls /api/products (fetch) and /api/categories (XHR) on page load.
 * Dynamically calls /api/search (fetch POST) on Search button click.
 * Dynamically calls /api/products/{id} (fetch GET) on Details button click.
 * Dynamically calls /api/cart (fetch POST) on Add to Cart button click.
 */

document.addEventListener("DOMContentLoaded", () => {
  loadCategories();
  loadProducts();
  setupEventListeners();
});

function loadCategories() {
  const xhr = new XMLHttpRequest();
  xhr.open("GET", "/api/categories");
  xhr.onload = function () {
    if (xhr.status === 200) {
      try {
        const categories = JSON.parse(xhr.responseText);
        const list = document.getElementById("categories-list");
        if (list) {
          list.innerHTML = "";
          categories.forEach((cat) => {
            const li = document.createElement("li");
            li.textContent = cat.name;
            list.appendChild(li);
          });
        }
      } catch (err) {
        console.error("Failed to parse categories:", err);
      }
    }
  };
  xhr.send();
}

function loadProducts() {
  fetch("/api/products")
    .then((res) => res.json())
    .then((products) => {
      renderProducts(products);
    })
    .catch((err) => console.error("Failed to load products:", err));
}

function renderProducts(products) {
  const container = document.getElementById("products-list");
  if (!container) return;
  container.innerHTML = "";
  if (!Array.isArray(products) || products.length === 0) {
    container.textContent = "No products found.";
    return;
  }
  products.forEach((p) => {
    const card = document.createElement("div");
    card.className = "card";
    card.id = `product-card-${p.id}`;

    const title = document.createElement("h3");
    title.textContent = p.name;
    card.appendChild(title);

    const price = document.createElement("p");
    price.textContent = `Price: $${p.price}`;
    card.appendChild(price);

    const btnDetails = document.createElement("button");
    btnDetails.type = "button";
    btnDetails.id = `btn-details-${p.id}`;
    btnDetails.textContent = "View Details";
    btnDetails.addEventListener("click", () => fetchProductDetails(p.id));
    card.appendChild(btnDetails);

    const btnCart = document.createElement("button");
    btnCart.type = "button";
    btnCart.id = `btn-cart-${p.id}`;
    btnCart.textContent = "Add to Cart";
    btnCart.addEventListener("click", () => addToCart(p.id, 1));
    card.appendChild(btnCart);

    container.appendChild(card);
  });
}

function setupEventListeners() {
  const searchBtn = document.getElementById("btn-search");
  if (searchBtn) {
    searchBtn.addEventListener("click", () => {
      const input = document.getElementById("search-input");
      const keyword = input ? input.value : "test";
      fetch("/api/search", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ keyword })
      })
        .then((res) => res.json())
        .then((data) => {
          renderProducts(data.results || []);
        })
        .catch((err) => console.error("Search failed:", err));
    });
  }
}

function fetchProductDetails(id) {
  fetch(`/api/products/${id}`)
    .then((res) => res.json())
    .then((item) => {
      const details = document.getElementById("details-view");
      if (details) {
        details.innerHTML = `<strong>${item.name}</strong>: ${item.description} ($${item.price})`;
      }
    })
    .catch((err) => console.error("Details fetch failed:", err));
}

function addToCart(productId, quantity) {
  fetch("/api/cart", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ productId, quantity })
  })
    .then((res) => res.json())
    .then((res) => {
      const cart = document.getElementById("cart-status");
      if (cart) {
        cart.textContent = `Added item ${res.productId} (qty: ${res.quantity}) to cart.`;
      }
    })
    .catch((err) => console.error("Add to cart failed:", err));
}
