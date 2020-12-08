for profile in "$PROFILE_DIR"/*.profile; do
        sed -i -E \
                -e "/^dbus-system none$/c\\blacklist /run/dbus" \
                -e "/^dbus-user none$/c\\blacklist \${RUNUSER}/bus\nenv DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$UID/bus" \
                -e "/^dbus-(user|system) (allow|filter)$/d" \
                -e "/^dbus-(user|system)\.(own|talk) .*$/d" \
                "$profile"
done
