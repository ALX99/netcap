#pragma once

#define ansi_clear() printf("\033[H\033[J")
#define ansi_goto(x, y) printf("\033[%d;%dH", (y), (x))
#define ansi_save() printf("\033[s")
#define ansi_restore() printf("\033[u")