#include <net/tcp.h>

u8 tcp_eno_global_subopt(const u8 *opt)
{
	int i;
	/* Global Suboption bytes are in range 0x00..0x1F
	 * We only care about the first, as the remainder are reserved
	 * 
	 */
	for (i = 2; i < opt[1]; i++) {
		if (opt[i] < 0x20)
			return opt[i]; 

		/* Skip TEPs */
		if (opt[i] < 0x80)
			continue;

		/* Skip TEP length bytes
		 * 
		 * The bottom 5 bits encode a length L
		 * They're immediately followed by a TEP suboption
		 * and then by L+1 bytes of suboption data
		 * Therefore our total skip should be L+2 bytes
		 */
		if (opt[i] < 0xA0)
			i += (opt[i] & 0x1F) + 2;

		/* opt[i] >= 0xA0
		 *
		 * TEP byte with implicit (to end of option) length
		 * So we just stop here
		 */
		break;

	}

	/* "A SYN segment without an explicit global suboption has an implicit
     *  global suboption of 0x00."
     */
	return 0;
}

static u8 tcp_eno_next_tep(const u8 *opt, int *i)
{
	for (; *i < opt[1]; (*i)++) {
		u8 b = opt[*i];
		/* Skip GSO byte */
		if (b < 0x20)
			continue; 

		/* TEP byte */
		if (b < 0x80)
			return (*i)++, b;
			
		/* TEP length byte */
		if (b < 0xA0) {
			int l = b & 0x1F;
			u8 tep;

			/* discard incomplete suboption */
			if (*i + l + 2 > opt[1])
				return 0;

			tep = opt[*i + 1];
			if (tep < 0x9F) {
				/* GSO, TEP byte or a length byte. All are invalud */
				return 0;
			}

			*i += l + 2;
			return tep & 0x7F;
		}

		/* >= 0xA0, TEP to end of buffer */
		*i = opt[1];
		return b & 0x7F;
	}

	return 0;
}

static bool tcp_eno_has_tep(const u8 *opt, u8 want_tep) 
{
	int i = 2;
	u8 tep;
	while ((tep = tcp_eno_next_tep(opt, &i))) {
		if (tep == want_tep)
			return true;
	}

	return false;
}

u8 tcp_eno_can_enable(const u8 *our_opt, const u8 *their_opt)
{
	const u8 *passive_opt, *active_opt;
	int i;
	u8 our_gso   = tcp_eno_global_subopt(our_opt);
	u8 their_gso = tcp_eno_global_subopt(their_opt);
	u8 selected_tep = 0, tep;

	bool we_are_active   = !!(our_gso   & TCP_ENO_GSO_PARTY_B);
	bool they_are_active = !!(their_gso & TCP_ENO_GSO_PARTY_B);

	/* Can't enable if we've both picked the same party */
	if (we_are_active == they_are_active)
		return 0;

	/* The selected TEP is the last common one selected by the 
	 * passive initiator */

	passive_opt = we_are_active ? their_opt : our_opt;
	active_opt  = we_are_active ? our_opt   : their_opt;

	i = 2;
	while ((tep = tcp_eno_next_tep(passive_opt, &i))) {
		if (tcp_eno_has_tep(active_opt, tep))
			selected_tep = tep;
	}

	return selected_tep;	
}
