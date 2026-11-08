/* Host shim: lwIP platform macros. */
#pragma once
#include <stdio.h>
#include <stdlib.h>
#define LWIP_PLATFORM_DIAG(x) do { printf x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { fprintf(stderr, "lwip assert: %s\n", x); abort(); } while (0)
