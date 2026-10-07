#!/usr/bin/env python3
"""Generate a deterministic synthetic multistream bzip2 Wikipedia dump for benchmarking.

Each bzip2 member is compressed independently and concatenated, mimicking the
multistream layout of real enwiki dumps. Page content is deterministic
(seed-fixed) and includes the edge cases the optimization plan requires:

  - benchmark keywords: "quantum" (common, mixed case), "xylophone" (rare),
    "R&D" (stored XML-escaped as "R&amp;D" -- exercises the OPT-06 rule)
  - titles with underscores, one non-ASCII title ("Café_culture")
  - pages with other escaped entities ("&lt;em&gt;")
  - a majority of pages containing no keyword at all

Usage:
    FIX_MEMBERS=800 FIX_PAGES=50 python3 bench/gen_fixture.py [outpath]

Defaults write to bench/fixture.xml.bz2 next to this script.
"""
import bz2
import os
import random
import sys

SEED = 20261004
MEMBERS = int(os.environ.get("FIX_MEMBERS", "800"))
PAGES_PER_MEMBER = int(os.environ.get("FIX_PAGES", "50"))

WORDS = (
    "time people way day man thing woman life child world school state family student group "
    "country problem hand part place case week company system program question work night point "
    "home water room mother area money story fact month lot right study book eye job word business "
    "issue side kind head house service friend father power hour game line end member law car "
    "community name team minute idea kid body information back parent face others level office "
    "door health person art war history party result change morning reason research girl guy "
    "moment air teacher force education river science music stone star energy light field forest "
    "mountain island desert ocean cloud rain snow wind fire earth metal glass paper cloth salt "
    "sugar bread milk cheese apple orange banana grape lemon peach pear plum berry cherry melon "
    "garden flower tree leaf root branch seed soil grass meadow hill valley plain plateau canyon "
    "bridge road street avenue lane path trail track station harbor airport market shop store "
    "bank church temple mosque school library museum theater cinema hotel inn farm ranch mine "
    "well spring lake pond pool stream brook creek ditch fence wall gate tower castle fort "
    "palace cabin hut tent boat ship ferry canoe raft sail oar anchor deck mast hull cargo "
    "wheel axle gear spring lever pulley rope chain hook nail screw bolt nut pin needle thread "
    "button zipper pocket sleeve collar cuff belt buckle shoe boot sandal glove hat cap coat "
    "shirt pants skirt dress suit vest tie scarf shawl blanket sheet towel soap brush comb "
    "mirror lamp candle torch lantern bulb wire plug switch dial knob button panel screen key "
    "lock hinge latch bolt bar beam plank board brick tile slate shingle straw reed bamboo "
    "cork bark moss fern ivy vine thorn petal stem bulb tuber grain wheat rice corn oat barley "
    "rye bean pea lentil nut almond walnut chestnut hazel acorn pine cone needle bark resin "
    "amber coal oil gas vapor steam smoke ash dust sand clay mud gravel pebble rock boulder "
    "crystal gem pearl coral shell scale feather fur wool silk cotton linen hemp flax jute "
    "ink paint dye chalk crayon pencil pen paper card board box crate barrel basket bag sack "
    "jar jug pot pan kettle cup mug bowl plate dish tray spoon fork knife ladle whisk grater "
    "stove oven grill hearth chimney flue vent fan pump pipe valve gauge meter clock watch "
    "timer bell horn drum flute harp lute lyre organ piano violin cello trumpet trombone tuba "
    "choir verse chorus rhyme meter stanza prose novel tale myth legend fable parable proverb "
    "riddle joke storyteller bard minstrel actor dancer singer player clown mime mask costume "
    "stage curtain scene act play opera ballet circus parade festival feast fast vigil rite "
    "charm spell potion elixir herb root bark leaf petal sap resin gum wax honey milk egg "
    "nest burrow den lair hive web cocoon shell molt scale fin gill claw hoof paw talon beak "
    "wing feather plume crest mane tail horn antler tusk fang sting stinger venom honeycomb "
    "pollen nectar dew frost mist fog haze glare gleam glow spark flash flicker flame ember "
    "sparkle shimmer ripple wave tide surf foam spray mist rainbow halo corona aurora comet "
    "meteor orbit planet moon sun star galaxy nebula quasar pulsar void"
).split()

COMMON_FORMS = ["quantum", "Quantum", "QUANTUM"]


def make_text(rng, page_idx):
    n = rng.randint(180, 320)
    words = [rng.choice(WORDS) for _ in range(n)]
    roll = rng.random()
    if roll < 0.40:
        # common keyword, random case form
        words[rng.randrange(n)] = rng.choice(COMMON_FORMS)
        if rng.random() < 0.25:
            words[rng.randrange(n)] = rng.choice(COMMON_FORMS)
    elif roll < 0.42:
        words[rng.randrange(n)] = "xylophone"  # rare keyword
    elif roll < 0.435:
        # entity keyword: source-escaped, unescapes to R&D
        words[rng.randrange(n)] = "R&amp;D"
    elif roll < 0.45:
        words[rng.randrange(n)] = "&lt;em&gt;not-a-keyword&lt;/em&gt;"
    if page_idx % 97 == 0:
        words.append("naïve café résumé")  # non-ASCII running text
    return " ".join(words)


def page_xml(pid, title, text):
    return (
        "<page><title>" + title + "</title><ns>0</ns><id>" + str(pid) + "</id>"
        "<revision><id>" + str(pid) + "</id>"
        '<text xml:space="preserve">' + text + "</text>"
        "</revision></page>\n"
    )


def main():
    outpath = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "fixture.xml.bz2"
    )
    rng = random.Random(SEED)
    pid = 1000
    with open(outpath, "wb") as out:
        for m in range(MEMBERS):
            pages = []
            for _ in range(PAGES_PER_MEMBER):
                if pid == 1000:
                    title = "Café_culture"  # non-ASCII + underscore title
                else:
                    title = "Test_Page_%d" % pid
                pages.append(page_xml(pid, title, make_text(rng, pid)))
                pid += 1
            chunk = "".join(pages).encode("utf-8")
            out.write(bz2.compress(chunk, compresslevel=9))
            if (m + 1) % 100 == 0:
                print("  ... %d/%d members" % (m + 1, MEMBERS), flush=True)
    total_pages = MEMBERS * PAGES_PER_MEMBER
    print("wrote %s (%d members, %d pages)" % (outpath, MEMBERS, total_pages))


if __name__ == "__main__":
    main()
