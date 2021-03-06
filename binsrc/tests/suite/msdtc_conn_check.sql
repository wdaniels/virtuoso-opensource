--  
--  $Id$
--  
--  This file is part of the OpenLink Software Virtuoso Open-Source (VOS)
--  project.
--  
--  Copyright (C) 1998-2012 OpenLink Software
--  
--  This project is free software; you can redistribute it and/or modify it
--  under the terms of the GNU General Public License as published by the
--  Free Software Foundation; only version 2 of the License, dated June 1991.
--  
--  This program is distributed in the hope that it will be useful, but
--  WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
--  General Public License for more details.
--  
--  You should have received a copy of the GNU General Public License along
--  with this program; if not, write to the Free Software Foundation, Inc.,
--  51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
--  
--  


-- mts_connect(0);
-- ECHO BOTH $IF $EQU $STATE OK  "PASSED" "***FAILED";
-- ECHO BOTH ": mts_connect() : STATE=" $STATE "\n";

select mts_status ('MTS');
ECHO BOTH $IF $EQU $LAST[1] 'connected' "PASSED" "***FAILED";
ECHO BOTH ": server " $LAST[1] " to MS DTC\n";
