/* error.c
 *
 * $Id: error.c 1 2010-04-11 21:04:36 vijay mohan $
 *
 * PacketSquare-capedit - Pcap Edit & Replay Tool
 * By vijay mohan <vijaymohan@packetsquare.com>
 * Copyright 2010 vijay mohan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <gtk/gtk.h>

extern GtkWidget *top_level;

char err_msg[255];
unsigned int err_val;

void
error_top_level ()
{
  GtkWidget *dialog;
  dialog = gtk_message_dialog_new (GTK_WINDOW(top_level), GTK_DIALOG_MODAL,
                                   GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
                                   err_msg,NULL);
  gtk_window_set_title (GTK_WINDOW (dialog), "Error");
  gtk_dialog_run (GTK_DIALOG (dialog));
  gtk_widget_destroy (dialog);
}

error_dialog(char *msg)
{
  GtkWidget *dialog;
  dialog = gtk_message_dialog_new (GTK_WINDOW(top_level), GTK_DIALOG_MODAL,
                                   GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
                                   msg, NULL);
  gtk_window_set_title (GTK_WINDOW (dialog), "Input Error");
  gtk_dialog_run (GTK_DIALOG (dialog));
  gtk_widget_destroy (dialog);
}

void
error_val ()
{
	if (err_val == 1) {
		error_dialog("Wrong IP Address - please enter correct IP Address {Ex:192.168.1.1}");
	} else if (err_val == 2) {
		error_dialog("Wrong MAC Address - please enter correct MAC Address {Ex:00:1C:FE:96:C3:0E}");
	} else if (err_val == 3) {
		error_dialog("Not a HEX value - please enter correct HEX value {Ex:0x23}");
	} else if (err_val == 4) {
		error_dialog("Must be 0 or 1");
	} else if (err_val == 5) {
		error_dialog("Wrong IPv6 Address - Not in presentation format");
	}

}
