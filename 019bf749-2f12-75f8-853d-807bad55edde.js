(function() {
  "use strict";

  // Korrekt strukturierte Daten für die Navigation
  const rootArray = [
    { 
      name: "Hauptnavigation",  // Titel der Navigation
      nav: [  // Array der Navigationseinträge
        {
          name: "Startseite",  // Navigationseintrag für Startseite
          navIcon: ""  // Kein Icon für "Startseite"
        },
        {
          name: "Über uns",  // Navigationseintrag für Über uns
          navIcon: ""  // Kein Icon für "Über uns"
        },
        {
          name: "Leistungen",  // Navigationseintrag für Leistungen
          navIcon: ""  // Kein Icon für "Leistungen"
        },
        {
          name: "Referenzen",  // Navigationseintrag für Referenzen
          navIcon: ""  // Kein Icon für "Referenzen"
        },
        {
          name: "Kontakt",  // Navigationseintrag für Kontakt
          navIcon: ""  // Kein Icon für "Kontakt"
        }
      ]
    }
  ];

  // Container, in den die Navigation eingefügt wird
  const container = document.getElementById('root');
  const navContainer = document.createElement('nav');

  // Iteriere über das rootArray
  rootArray.forEach(rootItem => {
    const sectionTitle = document.createElement('h1');
    sectionTitle.textContent = rootItem.name;  // Zeigt den Titel der Navigation (z.B. "Hauptnavigation")
    navContainer.appendChild(sectionTitle);

    // Iteriere über das nav-Array, um Navigationseinträge zu erstellen
    rootItem.nav.forEach(item => {
      const navItem = document.createElement('div');
      navItem.classList.add('nav-item');

      const iconContainer = document.createElement('span');
      
      // Prüfe, ob ein navIcon vorhanden ist
      if (item.navIcon) {
        iconContainer.innerHTML = item.navIcon;  // SVG direkt einfügen
      }

      // Füge den Namen des Navigationseintrags hinzu
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
