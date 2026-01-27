(function() {
  "use strict";

  // Array mit Objekten, die den SVG-Code als navIcon enthalten
  const rootArray = [
    { name: "javascript-design" },
    nav:[
    
    {
      name: "menu",
      navIcon: "<svg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24'><path d='M4 6h16M4 12h16M4 18h16' stroke='black' stroke-width='2' stroke-linecap='round'/></svg>"
    }
    ]
  ];

  const container = document.getElementById('root');
  const navContainer = document.createElement('nav');

  rootArray.forEach(item => {
    const navItem = document.createElement('div');
    navItem.classList.add('nav-item');

    const iconContainer = document.createElement('span');
    if (item.navIcon) {
      iconContainer.innerHTML = item.navIcon; // SVG direkt einfügen
    }

    const name = document.createElement('span');
    name.textContent = item.name || '';

    navItem.appendChild(iconContainer);
    navItem.appendChild(name);
    navContainer.appendChild(navItem);
  });

  container.appendChild(navContainer);

})();
