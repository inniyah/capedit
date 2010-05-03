/* tags.h
 *
 * $Id: tags.h 1 2010-04-14 23:50:30 vijay mohan $
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

#ifndef __TAGS_H__
#define __TAGS_H__

uint8_t
add_mtag (struct pak_file_info *fpak_info, uint16_t label, uint16_t exp, uint16_t stack, uint16_t ttl);

void
add_vtag(struct pak_file_info *fpak_info, uint16_t priority, uint16_t cfi, uint16_t id);

#endif
