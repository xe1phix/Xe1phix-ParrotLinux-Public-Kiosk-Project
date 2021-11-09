
List of Hexchat Settings.md


away_auto_unmark 	Toggle automatically unmarking away before message send.
away_omit_alerts 	Toggle omitting alerts when marked as being away.
away_reason 	Default away reason.
away_show_message 	Toggle announcing of away messages.
away_show_once 	Show identical away messages only once.
away_size_max 	How many users can be away in userlist before they are not colored.
away_timeout 	How often in seconds to check for max size for colors in userlist.
away_track 	Toggle color change for away users in userlist.
completion_amount 	How may nicks starting with input there should be before all are shown in text box. (E.g. if you have ‘k’ and completion_amount is set to 6, and there are 6 more people beginning with ‘k’ in the userlist, then all of the nicks starting with that are shown in the text box. To always cycle nicks, set to 123456 (or any other high number).
completion_auto 	Toggle automatic nick completion.
completion_sort 	Toggle nick completion sorting in “last talk” order.
completion_suffix 	Suffix to be appended to nicks after completion.
dcc_auto_chat 	Toggle auto accept for DCC chats.
dcc_auto_recv 	

How to accept DCC transfers.

    0=Ask for confirmation
    1=Ask for download folder
    2=Save without interaction

dcc_auto_resume 	Toggle auto resume of DCC transfers.
dcc_blocksize 	The blocksize for DCC transfers.
dcc_completed_dir 	Directory to move completed files to.
dcc_dir 	Directory to download files to from DCC.
dcc_fast_send 	Toggle speed up of DCC transfers by not waiting to heard if last part was received before sending next (currently disabled on Win32).
dcc_global_max_get_cps 	Max file transfer speed for all downloads combined in bytes per second.
dcc_global_max_send_cps 	Max file transfer speed for all uploads combined in bytes per second.
dcc_ip 	DCC IP address to bind to.
dcc_ip_from_server 	Get address from IRC server.
dcc_max_get_cps 	Max file transfer speed for one download in bytes per second.
dcc_max_send_cps 	Max file transfer speed for one upload in bytes per second.
dcc_permissions 	What permissions to set on received files. (It’s a CHMOD value in decimal, e.g. to CHMOD a file to 644, which is octal, you need to set dcc_permissions to 420, which is it’s decimal equivalent)
dcc_port_first 	First DCC port in range (leave ports at 0 for full range).
dcc_port_last 	Last DCC port in range (leave ports at 0 for full range).
dcc_remove 	Toggle automatic removal of finished/failed DCCs.
dcc_save_nick 	Toggle saving of nicks in filenames.
dcc_send_fillspaces 	Replace spaces in filenames with underscores.
dcc_stall_timeout 	Time in seconds to wait before timing out during a DCC send.
dcc_timeout 	Time in seconds to wait before timing out a DCC transfer waiting to be accepted.
flood_ctcp_num 	Number of CTCPs within flood_ctcp_time to be considered a flood.
flood_ctcp_time 	Time in seconds for use with flood_ctcp_num.
flood_msg_num 	Number of messages within flood_msg_time to be considered a flood.
flood_msg_time 	Time in seconds for use with flood_msg_num.
gui_autoopen_chat 	Toggle auto opening of Direct Chat Window on DCC Chat.
gui_autoopen_dialog 	Toggle auto opening of dialog windows.
gui_autoopen_recv 	Toggle auto opening of transfer window on DCC Recv.
gui_autoopen_send 	Toggle auto opening of transfer window on DCC Send.
gui_chanlist_maxusers 	Maximum number of users in channels to be listed in List of Channels.
gui_chanlist_minusers 	Minimum number of users in channels to be listed in List of Channels.
gui_compact 	Toggle compact mode (more or less spacing between user list/channel tree rows).
gui_dialog_height 	New dialog height in pixels.
gui_dialog_left 	The X co-ordinance of dialogs when opened.
gui_dialog_top 	The Y co-ordinance of dialogs when opened.
gui_dialog_width 	New dialog width in pixels.
gui_hide_menu 	Hide or unhide menu bar.
gui_input_icon 	Toggle user mode icon in the nick box.
gui_input_nick 	Toggle the nick box in the input box.
gui_input_spell 	Enable or disable spell checking.
gui_input_style 	Toggle use of text box colors and fonts in input box.
gui_join_dialog 	Toggle join dialog after connect.
gui_lagometer 	

Toggle types of Lag-O-Meters.

    0=Off
    1=Graph
    2=Text
    3=Both

gui_lang 	Set GUI language. Possible values are from 0 to 50 (Win32 only).
gui_mode_buttons 	Toggle mode buttons.
gui_pane_left_size 	Change size left pane.
gui_pane_right_size 	Change size right pane.
gui_pane_divider_position 	Saves position of divider when channel switcher and user list are on the same side.
gui_pane_right_size_min 	FIXME
gui_quit_dialog 	Toggle quit dialog.
gui_slist_fav 	Toggle showing favorites only in network list.
gui_slist_select 	The number of the server to select by default in the server list starting at 0. (E.g. to select the 67th server, set it to 66)
gui_slist_skip 	Toggle server list on startup.
gui_tab_chans 	Open channels in tabs instead of windows.
gui_tab_dialogs 	Open dialogs in tabs instead of windows.
gui_tab_dots 	Toggle dotted lines in the channel tree.
gui_tab_icons 	Toggle channel tree icons.
gui_tab_layout 	

Use treeview or tabs.

    0=Tabs
    2=Treeview

gui_tab_newtofront 	

When to focus new tabs.

    0=Never
    1=Always
    2=Only on requested tabs

gui_tab_pos 	

Set position of tabs.

    1=Left-Upper
    2=Left
    3=Right-Upper
    4=Right
    5=Top
    6=Bottom
    7=Hidden

gui_tab_server 	Open an extra tab for server messages.
gui_tab_small 	

Set small tabs.

    0=Off
    1=Small tabs
    2=Extra small tabs

gui_tab_sort 	Toggle alphabetical sorting of tabs.
gui_tab_trunc 	Number or letters to shorten tab names to.
gui_tab_utils 	Open utils in tabs instead of windows.
gui_throttlemeter 	

Toggle types of throttle meters.

    0=Off
    1=Graph
    2=Text
    3=Both

gui_topicbar 	Toggle topic bar.
gui_tray 	Enable system tray icon.
gui_tray_away 	Automatically mark away/back when the tray is toggled.
gui_tray_blink 	Toggle tray icon blinking or using static images.
gui_tray_close 	Close to tray.
gui_tray_minimize 	Minimize to tray.
gui_tray_quiet 	Only show tray balloons when hidden or iconified.
gui_ulist_buttons 	Toggle userlist buttons.
gui_ulist_count 	Toggle displaying user count on top of the user list.
gui_ulist_doubleclick 	Command to run upon double click of user in userlist.
gui_ulist_hide 	Hides userlist.
gui_ulist_icons 	Toggle use of icons instead of text symbols in user list.
gui_ulist_pos 	

Set userlist position.

    1=Left-Upper
    2=Left-Lower
    3=Right-Upper
    4=Right-Lower

gui_ulist_resizable 	Toggle resizable userlist.
gui_ulist_show_hosts 	Toggle user’s hosts displaying in userlist. (requires irc_who_join)
gui_ulist_sort 	

How to sort users in the userlist.

    0=A-Z with Ops first
    1=A-Z
    2=A-Z with Ops last
    3=Z-A
    4=Unsorted

gui_ulist_style 	Toggle use of text box colors and fonts in userlist.
gui_url_mod 	

How to handle URLs when clicked. (And what to hold.)

    0=Left Click Only
    1=Shift
    2=Caps Lock
    4=CTRL
    8=ALT

gui_usermenu 	Toggle editable usermenu.
gui_win_height 	Main window height in pixels.
gui_win_left 	The X co-ordinance of main window when opened.
gui_win_modes 	Show channel modes in title bar.
gui_win_save 	Toggles saving of state on exit.
gui_win_state 	

Default state of the main window.

    0=Not Maximized
    1=Maximized

gui_win_swap 	Swap the middle and left panes (allows side-by-side userlist/tree).
gui_win_top 	The Y co-ordinance of main window when opened.
gui_win_ucount 	Show number of users in title bar.
gui_win_width 	Main window width in pixels.
identd 	Toggle internal IDENTD (Win32 only).
input_balloon_chans 	Show tray balloons on channel messages.
input_balloon_hilight 	Show tray balloons on highlighted messages.
input_balloon_priv 	Show tray balloons on private messages.
input_balloon_time 	How long balloon messages should be displayed. (2.8.8+)
input_beep_chans 	Toggle beep on channel messages.
input_beep_hilight 	Toggle beep on highlighted messages.
input_beep_priv 	Toggle beep on private messages.
input_command_char 	Character used to execute commands. (E.g. if set to ‘[‘ then you would use commands like ‘[me jumps around’)
input_filter_beep 	Toggle filtering of beeps sent by others.
input_flash_chans 	Toggle whether or not to flash taskbar on channel messages.
input_flash_hilight 	Toggle whether or not to flash taskbar on highlighted messages.
input_flash_priv 	Toggle whether or not to flash taskbar on private messages.
input_perc_ascii 	Toggle interpreting of %nnn as ASCII value.
input_perc_color 	Toggle interpreting of %C, %B as color, bold, etc.
input_tray_chans 	Blink tray icon on channel messages.
input_tray_hilight 	Blink tray icon on highlighted messages.
input_tray_priv 	Blink tray icon on private messages.
irc_auto_rejoin 	Toggle auto rejoining when kicked.
irc_reconnect_rejoin 	Toggle auto rejoining on auto reconnect.
irc_ban_type 	

The default ban type to use for all bans. (requres irc_who_join)

    0=*!*@*.host
    1=*!*@domain
    2=*!*user@*.host
    3=*!*user@domain

irc_conf_mode 	

Toggle hiding of join, part and quit messages. (More info)

    0=Show join/part/quits
    1=Hide join/part/quits

irc_extra_hilight 	Extra words to highlight on.
irc_hide_version 	Toggle hiding of VERSION reply.
irc_id_ntext 	$4 in the channel message, channel message hilight and private message events if unidentified.
irc_id_ytext 	$4 in the channel message, channel message hilight and private message events if identified.
irc_invisible 	Toggle invisible mode (+i).
irc_join_delay 	How long to delay auto-joining a channel after connect.
irc_logging 	Toggle logging.
irc_logmask 	Mask used to create log filenames (strftime details: Windows Unix).
irc_nick1 	First choice nick.
irc_nick2 	Second choice nick.
irc_nick3 	Third choice nick.
irc_nick_hilight 	What nicks to highlight when they talk.
irc_notice_pos 	

Placement of Notices:

    0 = Automatic
    1 = Open extra (notices) tab
    2 = Always place in front tab

irc_no_hilight 	Nicks not to highlight on.
irc_part_reason 	Default reason when leaving channel.
irc_quit_reason 	Default quit reason.
irc_raw_modes 	Toggle RAW channel modes.
irc_real_name 	Real name to be sent to server.
irc_servernotice 	Toggle receiving of server notices.
irc_skip_motd 	Toggle skipping of server MOTD.
irc_user_name 	Username to be sent to server.
irc_wallops 	Toggle receiving wallops.
irc_who_join 	Toggle running WHO after joining channel.
irc_whois_front 	Toggle whois results being sent to currently active tab.
net_auto_reconnect 	Toggle auto reconnect to server.
net_auto_reconnectonfail 	Toggle auto reconnect upon failed connection. (Unix only command, not available on Windows)
net_bind_host 	Network address to bind HexChat to.
net_ping_timeout 	How long server ping has to be to timeout.
net_proxy_auth 	Toggle proxy authentication.
net_proxy_host 	Proxy host to use.
net_proxy_pass 	Password to use if proxy authentication is turned on.
net_proxy_port 	Port to use for proxy host.
net_proxy_type 	

Type of proxy to use.

    0=Disabled
    1=Wingate
    2=Socks4
    3=Socks5
    4=HTTP
    5=MS Proxy (ISA)

net_proxy_use 	

What to use proxies for (if set).

    0=All
    1=IRC Only
    2=DCC Only

net_proxy_user 	Username to use if proxy authentication is turned on.
net_reconnect_delay 	How many seconds to wait before reconnection.
net_throttle 	Toggle flood protection (to keep from getting kicked).
notify_timeout 	How often in seconds to check for users in your notify list.
notify_whois_online 	Toggle performing WHOIS on users on your notify list when they come online.
perl_warnings 	Toggle perl warnings.
sound_dir 	Directory where sounds are located.
stamp_log 	Toggle timestamps in logs.
stamp_log_format 	Format to use for log timestamps (strftime details: Windows Unix).
stamp_text 	Toggle timestamps in text box.
stamp_text_format 	Format to use for timestamps in textbox (strftime details: Windows Unix).
text_autocopy_color 	Toggle automatic copying of color information.
text_autocopy_stamp 	Toggle automatic copying of time stamps.
text_autocopy_text 	Toggle automatic copying of selected text.
text_background 	Sets the background image for text box.
text_color_nicks 	Toggle colored nicks.
text_font 	All fonts to be used (main and alternative fonts combined, shouldn’t be edited manually).
text_font_main 	Primary font to be used.
text_font_alternative 	Alternative fonts to be used for glyphs not supported by the primary font.
text_indent 	Toggle text indentation.
text_max_indent 	Max pixels to indent text with.
text_max_lines 	Max number or scrollback lines.
text_replay 	Reloads conversation buffers on next startup.
text_search_case_match 	Toggle performing a case-sensitive search.
text_search_backward 	Toggle searching from newest text line to the oldest.
text_search_highlight_all 	Toggle highlighting all occurences and underlining of the current occurence.
text_search_follow 	Toggle search for newly arriving messages.
text_search_regexp 	Toggle regarding search string as a regular expression.
text_show_marker 	Toggle red marker line feature.
text_show_sep 	Toggle separator line.
text_spell_langs 	List of languages to have spelling for, by language codes, separated by commas.
text_stripcolor_msg 	Toggle stripping colors from messages.
text_stripcolor_replay 	Toggle stripping colors from scrollback.
text_stripcolor_topic 	Toggle stripping colors from topic.
text_thin_sep 	Use thin separator line instead of thick line.
text_transparent 	Toggle transparent background.
text_wordwrap 	Toggle wordwrap.
url_grabber 	Toggle URL grabber.
url_grabber_limit 	Limit the number of URLs handled by the url grabber.
url_logging 	Toggle logging URLs to <config>/url.log.





/set irc_hide_version on        ## CTCP Replies - To hide the default VERSION reply you must 





