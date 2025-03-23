import React, { useState } from "react";

const categories = [
  {
    title: "Category 1",
    links: [
      { href: "hello1.html", label: "Dashboard 1" },
      { href: "hello2.html", label: "Dashboard 2" },
      { href: "hello3.html", label: "Dashboard 3" },
    ],
  },
];

const Sidebar: React.FC = () => {
  const [openCategory, setOpenCategory] = useState<number | null>(null);

  const toggleCategory = (index: number) => {
    setOpenCategory((prevIndex) => (prevIndex === index ? null : index));
  };

  return (
    <div className="sidebar">
      <div className="logo">
        <a href="index.html" className="Home-link">
          NetLogAnalyzer
        </a>
      </div>
      <nav className="nav">
        <ul>
          {categories.map((cat, index) => (
            <li key={index}>
              <div
                className="dropdown-header"
                onClick={() => toggleCategory(index)}
              >
                {cat.title}
              </div>
              {openCategory === index && (
                <ul className="dropdown-links">
                  {cat.links.map((link, idx) => (
                    <li key={idx}>
                      <a href={link.href} className="link">
                        {link.label}
                      </a>
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
      </nav>
    </div>
  );
};

export default Sidebar;
