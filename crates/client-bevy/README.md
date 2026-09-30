# client-bevy

The reference 3D client (Bevy) on `client-core`: it renders the game
server's snapshots and sends input at a 20 Hz fixed step. CI does not
build it (it needs a display stack); run it with `make play-full`.

- Windows builds do **not** use Bevy dynamic linking (avoid MSVC LNK1189).
- Non-Windows can enable `dynamic_linking` for faster iteration.
