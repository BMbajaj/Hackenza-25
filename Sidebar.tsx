import React, { useState } from "react";

const categories = [
  {
    title: "RTT ACK Analysis",
    links: [
      { href: "hello1.html", label: "Conversation Analysis" },
      { href: "hello2.html", label: "Source IP Analysis" },
      { href: "hello3.html", label: "Network Traffic Overview" },
    ],
  },
  {
    title: "Protocol Analysis",
    links: [
      { href: "hello4.html", label: "Delta Time per Protocol" },
      { href: "hello5.html", label: "Sum of delta times per protocol" },
      {
        href: "hello6.html",
        label: "Graph of Sum of delta times per protocol",
      },
      { href: "hello7.html", label: "Top 5 Conversations per protocol" },
    ],
  },
  {
    title: "Packet Loss",
    links: [{ href: "hello8.html", label: "Total Lost Packets by Category" }],
  },
  {
    title: "Source Retransmission",
    links: [{ href: "hello9.html", label: "Retransmission Delays by IP" }],
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
          NetDelayAnalyzer
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
