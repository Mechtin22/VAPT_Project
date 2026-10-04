import {
    LayoutDashboard,
    ClipboardList,
    Bug,
    FileCode2,
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
            name: "HTTP Requests",
            path: "/http-requests",
            icon: FileCode2
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

            {/* BRAND */}
            <div className="brand">

                <div className="brand-icon">
                    <Shield size={24} />
                </div>

                <div>
                    <h2>VAPT</h2>
                    <span>Security Center</span>
                </div>

            </div>

            {/* NAVIGATION */}
            <span className="menu-label">
                MAIN MENU
            </span>

            <nav>

                {menuItems.map((item) => {

                    const Icon = item.icon;

                    return (
                        <NavLink
                            key={item.path}
                            to={item.path}
                            className={({ isActive }) =>
                                isActive ? "nav-link active" : "nav-link"
                            }
                        >
                            <Icon size={18} />

                            <span>
                                {item.name}
                            </span>
                        </NavLink>
                    );

                })}

            </nav>

            {/* FOOTER */}
            <div className="sidebar-footer">

                <span className="status-dot"></span>

                <div>
                    <strong>
                        Lab Environment
                    </strong>

                    <small>
                        Localhost Protected
                    </small>
                </div>

            </div>

        </aside>
    );
}

export default Sidebar;