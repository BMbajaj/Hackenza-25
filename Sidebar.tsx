import React, { useState } from "react";

const categories = [
  {
    title: "RTT ACK Analysis",
    links: [
      { href: "hello1.html", label: "Dashboard 1" },
      { href: "hello2.html", label: "Dashboard 2" },
      { href: "hello3.html", label: "Dashboard 3" },
    ],
  },
  {
    title: "Protocol Analysis",
    links: [
      { href: "hello4.html", label: "Dashboard 4" },
      { href: "hello5.html", label: "Dashboard 5" },
      { href: "hello6.html", label: "Dashboard 6" },
      { href: "hello7.html", label: "Dashboard 7" },
    ],
  },
  {
    title: "Packet Loss",
    links: [{ href: "hello8.html", label: "Dashboard 8" }],
  },
  {
    title: "Source Retransmission",
    links: [{ href: "hello9.html", label: "Dashboard 9" }],
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
