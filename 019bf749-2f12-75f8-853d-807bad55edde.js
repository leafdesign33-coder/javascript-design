(function() {
  "use strict";

  // Array mit einem Root-Element, das ein `nav`-Array enthält
  const rootArray = [
    { 
      name: "Main Navigation", 
      nav: [
        {
          name: "javascript-design",
          navIcon: "" // Kein Icon für "javascript-design"
        },
        {
          name: "menu",
          navIcon: "<svg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24'><path d='M4 6h16M4 12h16M4 18h16' stroke='black' stroke-width='2' stroke-linecap='round'/></svg>"
        }
      ]
    }
  ];

  const container = document.getElementById('root');
  const navContainer = document.createElement('nav');

  // Iteriere über das rootArray
  rootArray.forEach(rootItem => {
    const sectionTitle = document.createElement('h1');
    sectionTitle.textContent = rootItem.name; // Zeigt den Titel der Navigation (z.B. "Main Navigation")
    navContainer.appendChild(sectionTitle);

    // Iteriere über das nav-Array, um Navigationseinträge zu erstellen
    rootItem.nav.forEach(item => {
      const navItem = document.createElement('div');
      navItem.classList.add('nav-item');

      const iconContainer = document.createElement('span');
      
      // Prüfe, ob ein navIcon vorhanden ist
      if (item.navIcon) {
        iconContainer.innerHTML = item.navIcon; // SVG direkt einfügen
      }

      // Füge den Namen hinzu (für den Fall, dass `name` leer ist, wird ein Leerstring verwendet)
      const name = document.createElement('span');
      name.textContent = item.name || '';

      // Füge sowohl das Icon als auch den Namen in das navItem ein
      navItem.appendChild(iconContainer);
      navItem.appendChild(name);

      // Füge das navItem dem navContainer hinzu
      navContainer.appendChild(navItem);
    });
  });

  // Füge den gesamten navContainer in den Root-Container ein
  container.appendChild(navContainer);

})();
