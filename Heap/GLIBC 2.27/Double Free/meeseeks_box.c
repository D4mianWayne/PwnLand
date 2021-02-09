#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void welcome() {
    puts("                                                                                ");
    puts("                                     `.-:/o+:.`                                 ");
    puts("                               ``..-::/++++++////-.`                            ");
    puts("                         `.-.-:/osyyyyyyyhMMNNdyo/:+/:.`                        ");
    puts("                   `.-:/++-/syhhhhhhhhhhhhhmNMMMMMd-++++/-.                     ");
    puts("             `.-:+ossoooo:/hhhhhhhhhhhhhhhhhhhhhddd-oo++++++/:.`                ");
    puts("       `..-/ossso++///+++-:yhhhhhhhhhhhhhhhhhhhhhhs`/ossssssssso/-.`            ");
    puts("   .:/+osyso+/::::::::::. .//+osyyyyyhhhhyyyysso//:``-::::::::/+osso+:-.        ");
    puts("  ...-:+osss+/::::::::::  `-:::::///////////::::::-  -::::::::::::/+osso+:-`    ");
    puts("  .-:....-:+osso+++++++/-`  `..--:::::::::::---.`` `-::::::::::::/+oosys+/::-`  ");
    puts("  .+s++/-....-/+ooooooosss+:..`````````````````.-:+ossoo+///+oossso/::-..----:  ");
    puts("  .++``-/++/-....-:/+++++oyy/::::::--------:+oossooo++oooosso/:--.---://+++y::  ");
    puts("  .++    `.:s-.......-:/+oyo+/::::::::::::::oyo+++++++//:--..--::/++++/:-..h::  ");
    puts("  .++       +o............:+osso+/:::::::/++oys+//:--..----::+o+/:-.```````h::  ");
    puts("  ./o       `++-......:/-....-:+osso++osso+/:-..----::::::::/s.````````````h::  ");
    puts("  .:s`       `-/++:--+o:/++/-....-:++/:-..---://:::::::::::/s.`````````````h::  ");
    puts("  ..s:          `.:/o/`  `.-/++/-..`.-:://++++//s/::::::::+s.``````````````h::  ");
    puts("  ..:y.      .+o/-.``        ``-o+.`-:y/:--.````-s+//+++++/.```````````````y/-  ");
    puts("  ...+o   ./shhdddhs+.          /o.`-/y``````````.o/:-..`````````````````./s/-  ");
    puts("  ...:y :shdddydddddhh:         :o.`-:h```````````````.-:/oyy+-````````.+o+::-  ");
    puts("  ...:s ydddddydddddydh/        .y.`-:h.```````````-oyhdddddhhdy+-`````+s:::::  ");
    puts("  ...-y sdddddydddddyddd/       .y.`-:y-``````````+hdhddddddhhddddy+ ``/o:::::  ");
    puts("  ...-y odddddyddddhydddd+   `.:+o.`-:y/.```````.sddhyddddddhhdddddd.``/s:::::  ");
    puts("  .-/+o /dddddyhdddhhddddd/  /o/-..`-::+o+:````/hdddhhddddddhhdddddd:``/s:::::  ");
    puts("  ./s.` .dddddyhdddhhdddddo  /+....`-::::/y-`.ydddddhhddddddhhdddddd/``:s::::-  ");
    puts("  ./s    /ddddyhdddhhdddddo  /o.... ::::::y- oddddddhhddddddhhdddddd/``:y/:::-  ");
    puts("  ./s     /hddyhdddhydddddo  ++....`-:::::s: oddddddhyddddddhhddddds````-/+s/-  ");
    puts("  .:s      -hdyhddddydddddo  ++....`.:::::y: oddddddhhddddddyhddddo````````s/-  ");
    puts("  ./s       .shdddddydddho-  /o....`.:::::y.`:hdddddhhddddddhhddh/`````````s/-  ");
    puts("  .++        `:/oyhdyho:.    `o+...`-::::/y.``-ohdddhhddddddhhdy-``````````s/-  ");
    puts("  .+o-``    ./.` `.::`        `o+-.`-::/o+.`````.:shhhddddddhho````````````y/-  ");
    puts("  `.-/++:.`-s/++/.``           `+o.`-:oo-``````````./shhys+:.``````````````h::  ");
    puts("     ``.:/+o-...:/++:           -s.`-:h.``````````````..````..````````````.h::  ");
    puts("        ``.........-y-          :o.`-:y-```````````````.-:++os/.````.-:/++o+:-  ");
    puts("            `.......:s.         :s.`-:h`````````````.+oo+/::::+o//+oo+/::-..``  ");
    puts("               ``..../s-`       -s.`-/y````````````:s/::::::::::/::--.``        ");
    puts("                   `..-/o+-``   -s.`-:h```````````/s::::::::--..``              ");
    puts("                      ``.-/++/-`:s.`-:h.````.-/++oo:::---.``                    ");
    puts("                          `..-/oss.`-:h:/+ooo+/:--..``                          ");
    puts("                             ``..-. -:++/::--.``                                ");
    puts("                                 `. ---.``                                      ");
    puts("                                                                                ");
    puts("This is a Mr. Meeseeks Box.");
    puts("Let me show you how it works.");
}

void menu() {
    puts("");
    puts("+------------------+");
    puts("| Mr. Meeseeks Box |");
    puts("+==================+");
    puts("| 1: Create        |");
    puts("| 2: Show          |");
    puts("| 3: Delete        |");
    puts("| 4: Exit          |");
    puts("+------------------+");
    printf("> ");
}

#define MAXN 5
char* meeseeks[MAXN] = {0};

void init() {
    srand(time(0));
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}

void create() {
    puts("I'm Mr. Meeseeks! Look at me!");
    printf("Size: ");
    int sz;
    scanf("%d", &sz);
    char* ptr = malloc(sz);
    printf("Request: ");
    scanf("%s", ptr);
    for (int i = 0; i < MAXN; i++)
        if (!meeseeks[i])
            meeseeks[i] = ptr;
    if (rand() & 1)
        puts("Yesiree!");
    else
        puts("Can do!");
}

void show() {
    printf("ID: ");
    int id;
    scanf("%d", &id);
    if (0 <= id && id < MAXN && meeseeks[id])
        printf("%s", meeseeks[id]);
}

void delete() {
    printf("ID: ");
    int id;
    scanf("%d", &id);
    if (0 <= id && id < MAXN && meeseeks[id])
        free(meeseeks[id]);
    puts("All done!");
}

int main() {
    init();
    welcome();
    while (1) {
        menu();
        int choice;
        scanf("%d", &choice);
        switch (choice) {
            case 1:
                create();
                break;
            case 2:
                show();
                break;
            case 3:
                delete();
                break;
            case 4:
                exit(0);
            default:
                puts("Make sure to check out the episode \"Meeseeks and Destroy\".");
        }
    }
}
