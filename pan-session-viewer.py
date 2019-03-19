from PyQt5.QtWidgets import QMainWindow, QApplication, QMessageBox, QTableWidgetItem
from PyQt5.QtGui import QColor, QPalette
from PyQt5 import QtCore
from lxml import etree as lxml
import requests
import sys
import socket
import sqlite3
import datetime
from qt_pan_session_viewer_ui import Ui_MainWindow
from qt_session_detail_ui import Ui_SessionDetail


# suppress warnings from requests library
requests.packages.urllib3.disable_warnings()


##############################################
# API REQUEST FUNCTION
##############################################
def api_request(url, api_session, values):
    """
    API request driver
    values parameter must be a dictionary with the following format:
    {'type': _api_operation_type_, 'cmd': _command_, 'key': _key_}

    Returns contents of the server response, in unicode (direct output from requests.post().text)
    """

    try:
        return True, api_session.post(url, values, verify=False, timeout=10).text, None
    except api_session.exceptions.ConnectionError as error_api:
        return False, 'Error connecting to {url} - Check IP Address'.format(url=url), error_api
    except api_session.exceptions.Timeout as error_timeout:
        return None, 'Connection to {url} timed out, please try again'.format(url=url), error_timeout


##############################################
# GENERATE AND RETURN API KEY
##############################################
class ConnectThread(QtCore.QThread):

    # Declare our output signal
    connect_values = QtCore.pyqtSignal(dict)

    def __init__(self, ip, user, password, parent=None):
        super(ConnectThread, self).__init__(parent)
        self.is_running = True
        self.ip = ip
        self.user = user
        self.password = password
        self.url = None
        self.api_session = requests.Session()

    def run(self):

        self.valid = False

        connect_values = {
            'ip': None,
            'user': None,
            'password': None,
            'result': None,
            'response': None,
            'error': None,
            'url': None
        }

        # Make sure we received either an IP address or a DNS hostname that we can resolve to an IP
        try:
            socket.gethostbyname(self.ip)

        except socket.gaierror as os_error_ip:
            print(os_error_ip)
            connect_values['response'] = "Unable to Connect or Invalid IP address given"
            connect_values['error'] = os_error_ip

        else:
            connect_values['url'] = self.url = 'https://{ip}/api'.format(ip=self.ip)
            connect_values['ip'] = self.ip

            # Make sure a username has been entered, and that it doesn't contain spaces
            try:
                if self.user.isspace() or len(self.user) is 0:
                    raise AttributeError('invalid username')

            except AttributeError as error_user:
                connect_values['response'] = 'The Username field is blank'
                connect_values['error'] = error_user

            else:
                connect_values['user'] = self.user

                # Make sure a password has been entered, and that it doesn't contain spaces
                try:
                    if self.password.isspace() or len(self.password) is 0:
                        raise AttributeError('invalid password')

                except AttributeError as error_password:
                    connect_values['response'] = 'The Password field is blank'
                    connect_values['error'] = error_password

                else:
                    connect_values['password'] = self.password

                    # all fields valid
                    self.valid = True

            if self.valid:
                # If all inputs are good, generate the API key for subsequent API calls
                try:
                    # get API key
                    connect_values['result'], connect_values['response'], connect_values['error'] = self.keygen()

                    if connect_values['result']:
                        connect_values['api'] = connect_values['response']
                except lxml.ParseError as error_xml:
                    connect_values['response'] = "Is this a FW/Panorama IP/Hostname?"
                    connect_values['error'] = error_xml

        # emit signal values
        self.connect_values.emit(connect_values)

    ##############################################
    # KEYGEN API DRIVER
    ##############################################
    def keygen(self):
        """
        Get API key
        """

        values = {'type': 'keygen', 'user': self.user, 'password': self.password}
        result, response, error = api_request(self.url, self.api_session, values)

        try:
            # if API call was successful
            if result is True:
                return True, lxml.fromstring(response).find('.//key').text, None

            # if timeout
            elif result is None:
                raise requests.Timeout

            # if connection error
            else:
                raise ValueError('check IP address')

        # connection error
        except (IndexError, ValueError) as error_keygen:
            return False, 'Error obtaining API key from {ip}'.format(ip=self.ip), error_keygen

        # if error raised finding <key> in response
        except AttributeError:
            return False, 'Error obtaining API key from {ip}'.format(ip=self.ip), 'check credentials'

        # if timeout
        except requests.Timeout as error_timeout:
            return False, 'Connection to {ip} timed out, please try again'.format(ip=self.ip), error_timeout


##############################################
# GET CONFIG DATA TO FILL COMBO BOXES
##############################################
class GetRunningConfig(QtCore.QThread):

    combo_box_values = QtCore.pyqtSignal(dict)

    def __init__(self, api, url, parent=None):
        super(GetRunningConfig, self).__init__(parent)
        self.is_running = True
        self.api = api
        self.url = url
        self.api_session = requests.Session()

    def run(self):

        combo_box_values = {
            'result': None,
            'response': None,
            'error': None
        }

        values = {
            'type': 'op',
            'key': self.api,
            'cmd': '<show><config><saved>running-config.xml</saved></config></show>'
        }

        combo_box_values['result'], combo_box_values['response'], combo_box_values['error'] = api_request(self.url, self.api_session, values)

        self.combo_box_values.emit(combo_box_values)


##############################################
# GET SESSIONS FROM SESSION TABLE
##############################################
class GetSessionData(QtCore.QThread):

    get_session_values = QtCore.pyqtSignal(dict)

    def __init__(self, api, url, src_ip, src_port, dst_ip, dst_port, src_zone, dst_zone, src_intf, dst_intf, app_id, src_user, target_vsys, parent=None):
        super(GetSessionData, self).__init__(parent)
        self.is_running = True
        self.api = api
        self.url = url
        self.api_session = requests.Session()

        # Construct filter parameters for API query based on user-supplied search terms
        self.filters = dict()
        if len(src_ip) > 0:
            self.filters['source'] = '<source>{srcip}</source>'.format(srcip=src_ip)
        else:
            self.filters['source'] = ''

        if len(src_port) > 0:
            self.filters['source-port'] = '<source-port>{srcport}</source-port>'.format(srcport=src_port)
        else:
            self.filters['source-port'] = ''

        if len(dst_ip) > 0:
            self.filters['destination'] = '<destination>{dstip}</destination>'.format(dstip=dst_ip)
        else:
            self.filters['destination'] = ''

        if len(dst_port) > 0:
            self.filters['destination-port'] = '<destination-port>{dstport}</destination-port>'.format(dstport=dst_port)
        else:
            self.filters['destination-port'] = ''

        if src_zone != 'Any':
            self.filters['from'] = '<from>{srczone}</from>'.format(srczone=src_zone)
        else:
            self.filters['from'] = ''

        if dst_zone != 'Any':
            self.filters['to'] = '<to>{dstzone}</to>'.format(dstzone=dst_zone)
        else:
            self.filters['to'] = ''

        if src_intf != 'Any':
            self.filters['ingress-interface'] = '<ingress-interface>{srcintf}</</ingress-interface>'.format(srcintf=src_intf)
        else:
            self.filters['ingress-interface'] = ''

        if dst_intf != 'Any':
            self.filters['egress-interface'] = '<egress-interface>{dstintf}</egress-interface>'.format(dstintf=dst_intf)
        else:
            self.filters['egress-interface'] = ''

        if len(app_id) > 0:
            self.filters['application'] = '<application>{appid}</application>'.format(appid=app_id)
        else:
            self.filters['application'] = ''

        if len(src_user) > 0:
            self.filters['source-user'] = '<source-user>{srcuser}</source-user>'.format(srcuser=src_user)
        else:
            self.filters['source-user'] = ''

        if len(target_vsys) > 0:
            # If a target vsys is specified, send API command to set it for subsequent queries
            set_target_vsys = {
                'result': None,
                'response': None,
                'error': None
            }

            values = {
                'type': 'op',
                'key': self.api,
                'cmd': '<set><system><setting><target-vsys>{a}</target-vsys></setting></system></set>'.format(a=target_vsys)
            }

            set_target_vsys['result'], set_target_vsys['response'], set_target_vsys['error'] = api_request(self.url, self.api_session, values)

    def run(self):

        get_session_values = {
            'result': None,
            'response': None,
            'error': None
        }
#
        values = {
            'type': 'op',
            'key': self.api,
            'cmd': '<show><session><all><filter>{a}{b}{c}{d}{e}{f}{g}{h}{i}{j}</filter></all></session></show>'.format(
                a=self.filters['application'], b=self.filters['from'], c=self.filters['source'], d=self.filters['source-port'],
                e=self.filters['ingress-interface'], f=self.filters['to'], g=self.filters['destination'], h=self.filters['destination-port'],
                i=self.filters['egress-interface'], j=self.filters['source-user']
            )
        }

        get_session_values['result'], get_session_values['response'], get_session_values['error'] = api_request(self.url, self.api_session, values)

        self.get_session_values.emit(get_session_values)


##############################################
# SESSION AUTO REFRESH TIMER THREAD
##############################################
class RefreshTimerThread(QtCore.QThread):
    """
    Simple timer thread that emits a tick signal every 10 seconds
    Can be safely terminated at any time with no data loss
    """
    timer_tick = QtCore.pyqtSignal(int)

    def __init__(self, parent=None):
        super(RefreshTimerThread, self).__init__(parent)
        self.is_running = True

    def run(self):
        while self.is_running is True:
            self.sleep(10)
            self.timer_tick.emit(1)


##############################################
# GET DETAIL FOR SPECIFIC SESSION
##############################################
class GetDetailedSessions(QtCore.QThread):

    get_session_details = QtCore.pyqtSignal(dict)
    status_update = QtCore.pyqtSignal(str)

    def __init__(self, api, url, session_ids, parent=None):
        super(GetDetailedSessions, self).__init__(parent)
        self.is_running = True
        self.api = api
        self.url = url
        # session_ids must be a list of Session ID numbers
        self.session_ids = session_ids
        self.session_results = {}
        self.api_session = requests.Session()

    def run(self):
        get_session_details = {
            'result': None,
            'response': None,
            'error': None
        }

        # TEMPORARY TEST CODE
        api_query_totaltime = 0
        api_query_count = 0

        # Loop through all Session IDs to be retrieved
        for session_id in self.session_ids:
            values = {
                'type': 'op',
                'key': self.api,
                'cmd': '<show><session><id>{a}</id></session></show>'.format(a=session_id)
            }

            # TEMPORARY TEST CODE
            api_query_starttime = datetime.datetime.now()
            api_query_count += 1

            get_session_details['result'], get_session_details['response'], get_session_details['error'] = api_request(self.url, self.api_session, values)

            # TEMPORARY TEST CODE
            api_query_endtime = datetime.datetime.now()

            # Check if our query returned any results
            if get_session_details['result'] is True and lxml.fromstring(get_session_details['response']).get('status') == 'success':
                session_xml = lxml.fromstring(get_session_details['response'])
                self.session_results[session_id] = session_xml
                api_query_duration = api_query_endtime - api_query_starttime
                api_query_totaltime += api_query_duration.total_seconds()
            else:
                self.session_results[session_id] = 'Error getting session details'

        # TEMPORARY TEST CODE
        self.status_update.emit('GetDetailedSessions Thread Finished.  Average API query time {} seconds'.format(round((api_query_totaltime / api_query_count), 2)))

        self.get_session_details.emit(self.session_results)


##############################################
# SESSION DETAIL UI WINDOW
##############################################
class SessionDetailWindow(QMainWindow):
    def __init__(self, session_id, api, url, parent=None):
        super(SessionDetailWindow, self).__init__(parent)

        # setup main window
        QMainWindow.__init__(self)
        self.ui = Ui_SessionDetail()
        self.session_id = session_id
        self.api = api
        self.url = url
        self.ui.setupUi(self)

        # variables
        self._is_output = '<html>'

        ##############################################
        # BUTTON EVENTS/TRIGGERS
        ##############################################
        self.ui.btn_refresh.clicked.connect(self._get_session)
        self.ui.btn_close.clicked.connect(self.close)

        # Set label indicating session ID
        self.ui.lbl_session_id.setText(self.session_id)

        # Trigger function to get session data
        self._get_session()

    def _get_session(self):
        self.connect_thread_get_session = GetDetailedSessions(self.api, self.url, [self.session_id], parent=None)
        self.connect_thread_get_session.start()
        self.connect_thread_get_session.get_session_details.connect(self._populate_form)
        self.connect_thread_get_session.quit()

    def _populate_form(self, session_details):
        self._session = session_details[self.session_id]

        # Populate session detail form with data returned from firewall
        # NOTE: There are no XML 'attributes' present in the session entries, so we must look for the Element instead
        self.session = self._session.find(".//result")

        # Fill c2s values
        self.ui.lbl_c2s_srcip.setText(self._get_xml_text(self.session, './c2s/source') + ' [' + self._get_xml_text(self.session, './c2s/source-zone') + ']')
        self.ui.lbl_c2s_dstip.setText(self._get_xml_text(self.session, './c2s/dst'))
        self.ui.lbl_c2s_proto.setText(self._get_xml_text(self.session, './c2s/proto'))
        self.ui.lbl_c2s_srcport.setText(self._get_xml_text(self.session, './c2s/sport'))
        self.ui.lbl_c2s_dstport.setText(self._get_xml_text(self.session, './c2s/dport'))
        self.ui.lbl_c2s_state.setText(self._get_xml_text(self.session, './c2s/state'))
        self.ui.lbl_c2s_type.setText(self._get_xml_text(self.session, './c2s/type'))
        self.ui.lbl_c2s_srcuser.setText(self._get_xml_text(self.session, './c2s/src-user'))
        self.ui.lbl_c2s_dstuser.setText(self._get_xml_text(self.session, './c2s/dst-user'))

        # Fill s2c values
        self.ui.lbl_s2c_srcip.setText(self._get_xml_text(self.session, './s2c/source') + ' [' + self._get_xml_text(self.session, './s2c/source-zone') + ']')
        self.ui.lbl_s2c_dstip.setText(self._get_xml_text(self.session, './s2c/dst'))
        self.ui.lbl_s2c_proto.setText(self._get_xml_text(self.session, './s2c/proto'))
        self.ui.lbl_s2c_srcport.setText(self._get_xml_text(self.session, './s2c/sport'))
        self.ui.lbl_s2c_dstport.setText(self._get_xml_text(self.session, './s2c/dport'))
        self.ui.lbl_s2c_state.setText(self._get_xml_text(self.session, './s2c/state'))
        self.ui.lbl_s2c_type.setText(self._get_xml_text(self.session, './s2c/type'))
        self.ui.lbl_s2c_srcuser.setText(self._get_xml_text(self.session, './s2c/src-user'))
        self.ui.lbl_s2c_dstuser.setText(self._get_xml_text(self.session, './s2c/dst-user'))

        # Fill additional details
        self.ui.lbl_slot.setText(self._get_xml_text(self.session, './slot'))
        self.ui.lbl_dp.setText(self._get_xml_text(self.session, './cpu'))
        # self.ui.lbl_index.setText(self._get_xml_text(self.session,'./')
        self.ui.lbl_starttime.setText(self._get_xml_text(self.session, './start-time'))
        self.ui.lbl_timeout.setText(self._get_xml_text(self.session, './timeout'))
        self.ui.lbl_ttl.setText(self._get_xml_text(self.session, './ttl'))
        self.ui.lbl_bytes_c2s.setText(self._get_xml_text(self.session, './c2s-octets'))
        self.ui.lbl_bytes_s2c.setText(self._get_xml_text(self.session, './s2c-octets'))
        self.ui.lbl_pkts_c2s.setText(self._get_xml_text(self.session, './c2s-packets'))
        self.ui.lbl_pkts_s2c.setText(self._get_xml_text(self.session, './s2c-packets'))
        self.ui.lbl_vsys.setText(self._get_xml_text(self.session, './vsys'))
        self.ui.lbl_ingress_intf.setText(self._get_xml_text(self.session, './igr-if'))
        self.ui.lbl_application.setText(self._get_xml_text(self.session, './application'))
        self.ui.lbl_rule.setText(self._get_xml_text(self.session, './rule'))
        self.ui.lbl_logend.setText(self._get_xml_text(self.session, './sess-log'))
        self.ui.lbl_ager.setText(self._get_xml_text(self.session, './sess-ager'))
        self.ui.lbl_ha_update.setText(self._get_xml_text(self.session, './sess-ha-sync'))
        self.ui.lbl_layer7.setText(self._get_xml_text(self.session, './l7proc'))
        self.ui.lbl_url_filtering.setText(self._get_xml_text(self.session, './url-en'))
        self.ui.lbl_syncookies.setText(self._get_xml_text(self.session, './syncookie'))
        self.ui.lbl_term_host.setText(self._get_xml_text(self.session, './host-session'))
        self.ui.lbl_tunnel.setText(self._get_xml_text(self.session, './tunnel-session'))
        self.ui.lbl_cp.setText(self._get_xml_text(self.session, './captive-portal'))
        self.ui.lbl_egress_intf.setText(self._get_xml_text(self.session, './egr-if'))
        self.ui.lbl_nat_rule.setText(self._get_xml_text(self.session, './nat-rule'))
        self.ui.lbl_dnat.setText(self._get_xml_text(self.session, './nat-dst'))
        self.ui.lbl_srcnat.setText(self._get_xml_text(self.session, './nat-src'))
        self.ui.lbl_url_cat.setText(self._get_xml_text(self.session, './url-cat'))

        # Indicate time of last refresh
        self.ui.lbl_refreshtime.setText(datetime.datetime.now().strftime('%H:%M:%S'))

    def _get_xml_text(self, element, xpath):
        if element.find(xpath) is None:
            return 'N/A'
        else:
            return element.find(xpath).text

    #################################################
    # CLOSE EVENT
    #################################################
    def closeEvent(self, event):
        self.close()
        event.accept()


##############################################
# MAIN UI WINDOW
##############################################
class PanSessionViewerMainWindow(QMainWindow):
    def __init__(self):

        # setup main window
        QMainWindow.__init__(self)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # variables
        self._is_output = '<html>'

        # List of Session Detail window widgets (allows multiple instances of window)
        self.DetailWindows = []

        # Flag to skip quit dialog
        self.force_close = None

        # Flag that an auto refresh is in progress
        self.refresh_running = False

        # Initialize session table database
        db_con = sqlite3.connect(":memory:")

        # Initialize requests session for this window
        self.api_session = requests.Session()

        # Hide VSYS label and combo box until we need them
        self.ui.lbl_vsys.hide()
        self.ui.cbo_vsys.hide()

        try:
            db_con.execute("create table SESSIONS ("
                           "id integer primary key, "
                           "vsys text, "
                           "application text, "
                           "state text, "
                           "type text, "
                           "srczone text, "
                           "srcaddress text, "
                           "srcport text, "
                           "dstzone text, "
                           "dstaddress text, "
                           "dstport text);"
                           )

            self.db_cur = db_con.cursor()

        except sqlite3.Error as e:
            self._log('An Error Occurred: {}'.format(e.args[0]))

        ##############################################
        # BUTTON EVENTS/TRIGGERS
        ##############################################
        self.ui.button_quit.clicked.connect(self.close)
        self.ui.button_connect.clicked.connect(self._connect)
        self.ui.button_search.clicked.connect(self._search_sessions)
        self.ui.button_clear_log.clicked.connect(lambda: self.ui.output_area.clear())
        self.ui.button_clear_session_wnd.clicked.connect(self._init_session_table)
        self.ui.tableSessions.cellDoubleClicked.connect(self._show_session_detail)
        self.ui.chkbox_refresh_search.stateChanged.connect(self._set_refresh_timer)
        self.ui.btn_refresh_existing.clicked.connect(self._update_existing)
        self.ui.cbo_vsys.currentIndexChanged.connect(self._populate_vsys_zone)

        # Initialize session table widget
        self._init_session_table()

    ####################################################
    # LOG AREA OUTPUT
    ####################################################
    def _log(self, message):
        self.ui.output_area.append('> ' + str(datetime.datetime.now().time().strftime('%H:%M:%S ')) + message)

    ####################################################
    # AUTO REFRESH DISCOVERED SESSIONS TIMER
    ####################################################
    def _set_refresh_timer(self, chk_state):
        if chk_state == 2:
            # Perform actions
            self._log('Session Search Auto-Refresh ENABLED')
            # Initialize the refresh timer thread object
            self.timer_thread = RefreshTimerThread()
            self.timer_thread.start()
            self.timer_thread.timer_tick.connect(self._refresh_timer_run)

        else:
            self._log('Session Search Auto-Refresh DISABLED')
            self.timer_thread.terminate()

    ####################################################
    # CLEAR AND INITIALIZE SESSION TABLE DB AND WIDGET
    ####################################################
    def _init_session_table(self):
        # Clear SESSIONS table in database (database is already created when we run this)
        sql = 'DELETE FROM SESSIONS'
        try:
            self.db_cur.execute(sql)

        except sqlite3.Error as e:
            self._log(' An Error Occurred: {}'.format(e.args[0]))

        # Make sure output table is clear, and set headers
        self.ui.tableSessions.clear()
        self.ui.tableSessions.setColumnCount(11)
        self.ui.tableSessions.setRowCount(0)
        self.ui.tableSessions.setHorizontalHeaderLabels("Session ID;VSYS;Application;State;Type;Src Zone;Src Address;Src Port;Dst Zone;Dst Address;Dst Port".split(";"))

        # Update label showing current count
        self.ui.lbl_sessions_tracked.setText('Sessions Tracked: 0')

    ##############################################
    # RESET FLAGS
    ##############################################
    def _reset_flags(self):
        self._flag_tags = False
        self._flag_connect_success = False

    ##############################################
    # RESET BUTTON COLOR
    ##############################################
    def _reset_button_color(self):
        self.ui.button_connect.setStyleSheet('color: white; background-color: rgb(53,53,53);')
        self.ui.button_search.setStyleSheet('color: white; background-color: rgb(53,53,53);')

    ##############################################
    # RESET FLAGS and BUTTONS
    ##############################################
    def _reset_flags_buttons(self):
        self._reset_flags()
        self._reset_button_color()

    ##############################################
    # CONNECT
    ##############################################
    def _connect(self):
        # get/set IP and credentials (validate parameters)
        valid = False

        self.ui.label_status.setText('Connecting...')

        # clear all combo boxes
        self.ui.cbo_src_zone.clear()
        self.ui.cbo_dst_zone.clear()
        self.ui.cbo_src_intf.clear()
        self.ui.cbo_dst_intf.clear()

        # reset all flags & flags
        self._reset_flags_buttons()

        # start thread to connect to firewall
        self.connect_thread = ConnectThread(parent=None, ip=self.ui.ip_address.text(), user=self.ui.username.text(), password=self.ui.password.text())
        self.connect_thread.start()
        self.connect_thread.connect_values.connect(self._set_connect_values)
        self.connect_thread.quit()

    ##############################################
    # SET CONNECT VALUES
    ##############################################
    def _set_connect_values(self, values):

        if values['result']:
            self._api = values['api']
            self._ip = values['ip']
            self._user = values['user']
            self._password = values['password']
            self._url = values['url']
            self.ui.button_connect.setStyleSheet('background-color: green; color:white;')
            self.ui.button_connect.setText('Connected to: {ip}'.format(ip=self._ip))
            self.ui.label_status.clear()
            self.ui.button_search.setEnabled(True)

            # trigger functions to fill combo boxes
            self._system_info()

            self.connect_thread_get_config = GetRunningConfig(parent=None, api=self._api, url=self._url)
            self.connect_thread_get_config.start()
            self.connect_thread_get_config.combo_box_values.connect(self._fill_combo_boxes)
            self.connect_thread_get_config.quit()

        else:
            self.ui.button_connect.setStyleSheet('background-color: red; color:white;')
            self.ui.button_connect.setText('Connection Error: {ip}'.format(ip=values['ip']))
            self._show_critical_error([values['response'], values['error']])

    ##############################################
    # ADD SYSTEM INFO TO STATUS BAR
    ##############################################
    def _system_info(self):
        """
        Show System Info and HA State: update status bar with system details
        """

        values1 = {'type': 'op', 'cmd': '<show><system><info></info></system></show>', 'key': self._api}
        result1, response1, error1 = api_request(self._url, self.api_session, values1)

        values2 = {'type': 'op', 'cmd': '<show><high-availability><state></state></high-availability></show>', 'key': self._api}
        result2, response2, error2 = api_request(self._url, self.api_session, values2)

        # get device info
        if result1:
            root = lxml.fromstring(response1)
            model = root.findtext('.//model')
            self._device = root.findtext('.//devicename')
            self._sw = root.findtext('.//sw-version')

        # get HA info
        if result2:
            root2 = lxml.fromstring(response2)
            ha_mode = root2.findtext('.//group/mode')
            ha_state = root2.findtext('.//group/local-info/state')

            # set status bar
            self.ui.statusbar.showMessage('Model: {m} {x:5}|{x:5}Device Name: {d} {x:5}|{x:5}SW Version: {s} {x:5}|{x:5}HA Mode: {mode} {x:5}|{x:5}HA State: {state}'.format(m=model, d=self._device, s=self._sw, x='', mode=ha_mode, state=str(ha_state).upper()))

    ##############################################
    # POPULATE COMBO BOXES
    ##############################################
    def _fill_combo_boxes(self, values):
        """
        Sets the combo boxes showing zones and interfaces
        """

        # if we successfully loaded the running config...
        if values['result'] is True and lxml.fromstring(values['response']).get('status') == 'success':
            self._running_config = lxml.fromstring(values['response'])
            self._log('"{name}" has been loaded!'.format(name='running-config.xml'))

        else:
            self.ui.output_area.clear()
            self._log('Error loading "{name}". Please try again.'.format(name='running-config.xml'))
            self._log('{error}'.format(error=values['error']))
            return None

        # check if Panorama - if so, error out; we can only run against firewalls...
        panorama_exists = self._running_config.find('.//panorama')

        if panorama_exists is not None:
            self._show_critical_error(['The connected device is a Panorama unit!', 'This program only supports direct connection to a PAN-OS Firewall'])

        # Populate Interfaces combo boxes
        # NOTE: the names of interfaces exist as XML 'attributes' within each entry
        self.interfaces = ['Any']
        for ethernet in self._running_config.xpath('//config/devices/entry[@name=\'localhost.localdomain\']/network/interface/ethernet/entry'):
            self.interfaces.append(ethernet.get('name'))
        for aggregate_ethernet in self._running_config.xpath('//config/devices/entry[@name=\'localhost.localdomain\']/network/interface/aggregate-ethernet/entry'):
            self.interfaces.append(aggregate_ethernet.get('name'))
        for loopback in self._running_config.xpath('//config/devices/entry[@name=\'localhost.localdomain\']/network/interface/loopback/entry'):
            self.interfaces.append(loopback.get('name'))
        for vlan in self._running_config.xpath('//config/devices/entry[@name=\'localhost.localdomain\']/network/interface/vlan/entry'):
            self.interfaces.append(vlan.get('name'))
        for tunnel in self._running_config.xpath('//config/devices/entry[@name=\'localhost.localdomain\']/network/interface/tunnel/entry'):
            self.interfaces.append(tunnel.get('name'))

        self.ui.cbo_src_intf.addItems(self.interfaces)
        self.ui.cbo_dst_intf.addItems(self.interfaces)

        # Populate Zone combo boxes
        # NOTE: the names of zones exist as XML 'attributes' within each entry
        self.zones = ['Any']
        self.vsys_list = []

        for vsys in self._running_config.xpath('//config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry'):
            self.vsys_list.append(vsys.get('name'))

        if len(self.vsys_list) > 1:
            # We have more than one vsys - don't populate zone combo boxes until a selection is made
            self.vsys_list.insert(0, '--Please Choose--')
            self.ui.cbo_vsys.addItems(self.vsys_list)

            # Un-hide label and combo box to select vsys
            self.ui.lbl_vsys.show()
            self.ui.cbo_vsys.show()
            return

        else:
            # Otherwise proceed with what we have
            for zones in self._running_config.xpath('//config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/zone/entry'):
                self.zones.append(zones.get('name'))

            self.ui.cbo_src_zone.addItems(self.zones)
            self.ui.cbo_dst_zone.addItems(self.zones)

    ##############################################################
    # POPULATE VSYS SPECIFIC ZONES
    ##############################################################
    def _populate_vsys_zone(self, vsysbox_index):
        # Reset zone list and combo boxes
        self.zones.clear()
        self.zones = ['Any']
        self.ui.cbo_src_zone.clear()
        self.ui.cbo_dst_zone.clear()

        if vsysbox_index == 0:
            # 0 is the instructions - don't do anything
            return
        else:
            for zones in self._running_config.xpath('//config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'{vsysname}\']/zone/entry'.format(vsysname=self.vsys_list[vsysbox_index])):
                self.zones.append(zones.get('name'))

            # Alphabetize the zone list, then populate the combo boxes
            self.zones.sort()
            self.ui.cbo_src_zone.addItems(self.zones)
            self.ui.cbo_dst_zone.addItems(self.zones)

    ##############################################################
    # SEARCH SESSIONS
    ##############################################################
    def _search_sessions(self):
        self.connect_thread_get_sessions = GetSessionData(
            self._api, self._url,
            src_ip=self.ui.src_ip.text(),
            src_port=self.ui.src_port.text(),
            dst_ip=self.ui.dst_ip.text(),
            dst_port=self.ui.dst_port.text(),
            src_zone=self.ui.cbo_src_zone.currentText(),
            dst_zone=self.ui.cbo_dst_zone.currentText(),
            src_intf=self.ui.cbo_src_intf.currentText(),
            dst_intf=self.ui.cbo_dst_intf.currentText(),
            app_id=self.ui.appid.text(),
            src_user=self.ui.src_user.text(),
            target_vsys=self.ui.cbo_vsys.currentText(),
            parent=None
        )

        self.connect_thread_get_sessions.start()
        self.connect_thread_get_sessions.get_session_values.connect(self._display_sessions)
        self.connect_thread_get_sessions.quit()

    ##############################################################
    # POPULATE SESSION TABLE WIDGET
    ##############################################################
    def _display_sessions(self, session_values):
        # Check if our search returned any results
        if session_values['result'] is True and lxml.fromstring(session_values['response']).get('status') == 'success':
            self._session_table = lxml.fromstring(session_values['response'])
            self._log('Session Table query has been completed!')

        else:
            self.ui.output_area.clear()
            self._log('Error retrieving session table. Please try again.')
            self._log('{error}'.format(error=session_values['error']))
            return None

        # Populate table widget with sessions
        # NOTE: There is no XML 'attribute' present in the session entries, so we must look for the Element instead
        self.session_list = self._session_table.findall(".//entry")

        if len(self.session_list) > 0:
            # Check that we have at least one session in our search results
            for session in self.session_list:
                # Insert session into sqlite database; replace the existing entry if there's already one with the same ID
                sql = '''REPLACE INTO SESSIONS (id, vsys, application, state, type, srczone, srcaddress, srcport, dstzone, dstaddress, dstport) VALUES (?,?,?,?,?,?,?,?,?,?,?);'''
                try:
                    self.db_cur.execute(sql, [session.find('idx').text, session.find('vsys').text,
                                              session.find('application').text, session.find('state').text,
                                              session.find('type').text, session.find('from').text,
                                              session.find('source').text, session.find('sport').text,
                                              session.find('to').text, session.find('dst').text,
                                              session.find('dport').text])

                except sqlite3.Error as e:
                    self._log('An Error Occurred: {}'.format(e.args[0]))

            # Log how many entries we have in the database now
            sql = '''SELECT count(*) FROM SESSIONS;'''
            try:
                self.db_cur.execute(sql)
                count = self.db_cur.fetchone()[0]
                self._log('sqlite database now contains {a} entries'.format(a=count))
                self.ui.lbl_sessions_tracked.setText('Sessions Tracked {a}'.format(a=count))

            except sqlite3.Error as e:
                self._log('An Error Occurred: {}'.format(e.args[0]))

            # Erase session output table to prepare for update
            self.ui.tableSessions.clear()
            self.ui.tableSessions.setColumnCount(11)
            self.ui.tableSessions.setHorizontalHeaderLabels("Session ID;VSYS;Application;State;Type;Src Zone;Src Address;Src Port;Dst Zone;Dst Address;Dst Port".split(";"))

            # Get all sessions from database and add them to the table widget
            sql = '''SELECT * FROM SESSIONS;'''
            self.ui.tableSessions.setRowCount(0)
            try:
                self.db_cur.execute(sql)

            except sqlite3.Error as e:
                self._log('An Error Occurred: {}'.format(e.args[0]))

            for row, form in enumerate(self.db_cur):
                self.ui.tableSessions.insertRow(row)
                for column, item in enumerate(form):
                    self.ui.tableSessions.setItem(row, column, QTableWidgetItem(str(item)))

        else:
            # If no sessions matched our query, log it
            self._log('No sessions matched query!')

    ####################################################
    # AUTO REFRESH SESSION SEARCH
    ####################################################
    def _refresh_timer_run(self, event):
        self._log('Refresh Timer Tick')

        if self.refresh_running is True:
            # Don't run again if we haven't finished a previous refresh
            self._log('Last refresh not done yet - skipping')
            return None

        else:
            # Signal that a refresh operation is in progress
            self.refresh_running = True

            # Run function to perform search using current filter selections
            self._search_sessions()

            # Signal that we're done
            self.refresh_running = False

    ####################################################
    # GET CURRENT STATUS OF DISCOVERED SESSIONS IN TABLE
    ####################################################
    def _update_existing(self):
        # Check if there are any sessions to refresh, otherwise show an error and cancel further refreshes
        sql = '''SELECT count(*) FROM SESSIONS;'''
        try:
            self.db_cur.execute(sql)

        except sqlite3.Error as e:
            self._log('An Error Occurred: {}'.format(e.args[0]))

        # Disable button until we're done
        self.ui.btn_refresh_existing.setEnabled(False)

        # Initialize empty list for session IDs to refresh
        session_ids = list()

        # Get list of sessions to be refreshed
        sql = '''SELECT id FROM SESSIONS;'''
        try:
            self.db_cur.execute(sql)

        except sqlite3.Error as e:
            self._log('An Error Occurred: {}'.format(e.args[0]))

        # Request current details of each session and save them into database
        for row in self.db_cur:
            session_ids.append(row[0])

        self.connect_thread_get_session = GetDetailedSessions(self._api, self._url, session_ids, parent=None)
        self._log('GetDetailedSessions Thread Starting')
        self.connect_thread_get_session.start()
        self.connect_thread_get_session.get_session_details.connect(self._update_records)
        self.connect_thread_get_session.status_update.connect(self._log)
        self.connect_thread_get_session.quit()

    #####################################################
    # UPDATE TABLE WITH NEW SESSION STATUS INFO
    #####################################################
    def _update_records(self, session_details):
        # Update database records
        # NOTE: There are no XML 'attributes' present in the session entries, so we must look for the Element instead
        for session_id, session_xml in session_details.items():
            current_session = session_xml.find('.//result')

            try:
                self.db_cur.execute('''UPDATE SESSIONS SET application=?, state=? WHERE id=?;''',
                                    (current_session.find('application').text, current_session.find('./s2c/state').text,
                                     session_id))

            except sqlite3.Error as e:
                self._log('An Error Occurred: {}'.format(e.args[0]))

        # Erase session output table to prepare for update
        self.ui.tableSessions.clear()
        self.ui.tableSessions.setColumnCount(11)
        self.ui.tableSessions.setHorizontalHeaderLabels(
            "Session ID;VSYS;Application;State;Type;Src Zone;Src Address;Src Port;Dst Zone;Dst Address;Dst Port".split(
                ";"))

        # Re-populate table widget with updated details
        # Get all sessions from database and add them to the table widget
        sql = '''SELECT * FROM SESSIONS;'''

        self.ui.tableSessions.setRowCount(0)

        try:
            self.db_cur.execute(sql)

        except sqlite3.Error as e:
            self._log('An Error Occurred: {}'.format(e.args[0]))

        for row, form in enumerate(self.db_cur):
            self.ui.tableSessions.insertRow(row)
            for column, item in enumerate(form):
                self.ui.tableSessions.setItem(row, column, QTableWidgetItem(str(item)))

        # Re-Enable Refresh Button
        self.ui.btn_refresh_existing.setEnabled(True)

    ##############################################
    # SHOW CRITICAL ERROR
    ##############################################
    def _show_critical_error(self, message_list):

        message = '''
        <p>
        {message}
        <br>
        Error: {error}
        </p>
        '''.format(message=message_list[0], error=message_list[1])

        result = QMessageBox.critical(self, 'ERROR', message, QMessageBox.Abort, QMessageBox.Retry)

        # Abort
        if result == QMessageBox.Abort:
            self.force_close = True
            self.close()

        # Retry
        else:
            # set error flag to True -- implies error
            self._flag_error = True
            return

    #################################################
    # CLOSE EVENT
    #################################################
    def closeEvent(self, event):
        # If something triggered a force close, don't ask if the user wants to quit - that'd be silly
        if self.force_close is True:
            event.accept()

        else:
            # Give the user a choice
            reply = QMessageBox.question(self, 'Confirm', "Are you sure you want to quit?", QMessageBox.Yes, QMessageBox.No)

            if reply == QMessageBox.Yes:
                event.accept()
            else:
                event.ignore()

    #################################################
    # SHOW SESSION DETAIL WINDOW
    #################################################
    def _show_session_detail(self, row, column):
        # column variable not used here, but needs to be defined as it's included by the signal

        # Get the ID of the session that was clicked
        session_id = self.ui.tableSessions.item(row, 0).text()

        # Launch the new window, with necessary parameters included
        self.session_detail = SessionDetailWindow(session_id, self._api, self._url)
        self.session_detail.show()

        # Add window to a List of windows - allows multiple to be visible at once
        self.DetailWindows.append(self.session_detail)


############################################################################
# MAIN
############################################################################
if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    # Create color scheme
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, QtCore.Qt.white)
    palette.setColor(QPalette.Base, QColor(15, 15, 15))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, QtCore.Qt.white)
    palette.setColor(QPalette.ToolTipText, QtCore.Qt.white)
    palette.setColor(QPalette.Text, QtCore.Qt.white)
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, QtCore.Qt.white)
    palette.setColor(QPalette.BrightText, QtCore.Qt.red)
    palette.setColor(QPalette.Highlight, QColor(25, 193, 255).lighter())
    palette.setColor(QPalette.HighlightedText, QtCore.Qt.black)

    # Apply color scheme
    app.setPalette(palette)

    # Define main window, then show it
    main = PanSessionViewerMainWindow()
    main.show()

    # Execute the QApplication; exit the script when the application is closed
    sys.exit(app.exec_())
