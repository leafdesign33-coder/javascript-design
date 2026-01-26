(function() {
  "use strict";

  // Array mit Objekten, die den SVG-Code als navIcon enthalten
  const root = [
    { name: "javascript-design", navIcon: "<svg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24'><path d='M12 2L4 20h16L12 2z' fill='green'/></svg>" },
    { name: "html-design", navIcon: "<svg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24'><path d='M5 3v18h14V3H5z' fill='orange'/></svg>" },
    { name: "css-design", navIcon: "<svg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24'><path d='M10 2v20h4V2h-4z' fill='blue'/></svg>" }
  ];

  // Beispiel: Erstelle Navigation im HTML
  const navContainer = document.createElement('nav');
  root.forEach(item => {
    const navItem = document.createElement('div');
    navItem.classList.add('nav-item');

    // Füge das SVG Icon hinzu
    const iconContainer = document.createElement('span');
    iconContainer.innerHTML = item.navIcon;  // SVG-Code wird direkt eingefügt

    const name = document.createElement('span');
    name.textContent = item.name;

    navItem.appendChild(iconContainer);
    navItem.appendChild(name);
    navContainer.appendChild(navItem);
  });

  // Füge die Navigation in den HTML-Body ein
  document.body.appendChild(navContainer);

})();
