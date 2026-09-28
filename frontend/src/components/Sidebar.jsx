import {
    LayoutDashboard,
    ClipboardList,
    Bug,
    Image,
    RefreshCw,
    FileText,
    Shield
} from "lucide-react";

import { NavLink } from "react-router-dom";

function Sidebar() {
    const menuItems = [
        {
            name: "Dashboard",
            path: "/",
            icon: LayoutDashboard
        },
        {
            name: "Assessments",
            path: "/assessments",
            icon: ClipboardList
        },
        {
            name: "Findings",
            path: "/findings",
            icon: Bug
        },
        {
            name: "Evidence",
            path: "/evidence",
            icon: Image
        },
        {
            name: "Retesting",
            path: "/retesting",
            icon: RefreshCw
        },
        {
            name: "Reports",
            path: "/reports",
            icon: FileText
        }
    ];

    return (
        <aside className="sidebar">

            <div className="sidebar-logo">
                <div className="logo-icon">
                    <Shield size={24} />
                </div>

                <div>
                    <h2>VAPT</h2>
                    <span>Security Center</span>
                </div>
            </div>

            <nav className="sidebar-nav">

                <p className="nav-title">MAIN MENU</p>

                {menuItems.map((item) => {
                    const Icon = item.icon;

                    return (
                        <NavLink
                            key={item.path}
                            to={item.path}
                            className={({ isActive }) =>
                                `nav-item ${isActive ? "active" : ""}`
                            }
                        >
                            <Icon size={20} />
                            <span>{item.name}</span>
                        </NavLink>
                    );
                })}

            </nav>

            <div className="sidebar-footer">
                <div className="security-status">
                    <span className="status-dot"></span>

                    <div>
                        <strong>Lab Environment</strong>
                        <small>Localhost Protected</small>
                    </div>
                </div>
            </div>

        </aside>
    );
}

export default Sidebar;