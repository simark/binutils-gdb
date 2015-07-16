#include <stdint.h>

struct inner
{
  uint16_t a;
  uint16_t b[2];
};

struct outer
{
  uint16_t x;
  uint16_t y;

  struct inner inner;

  uint16_t z[2];
};

struct outer o;
struct inner i;

void
break_here (void)
{
}

int
main (void)
{
  o.x = 0x1111;
  o.y = 0x2222;

  o.inner.a = 0x3333;
  o.inner.b[0] = 0x4444;
  o.inner.b[1] = 0x5555;

  o.z[0] = 0x6666;
  o.z[1] = 0x7777;

  i.a = 0x8888;
  i.b[0] = 0x9999;
  i.b[1] = 0xaaaa;

  break_here ();

  return 0;
}
