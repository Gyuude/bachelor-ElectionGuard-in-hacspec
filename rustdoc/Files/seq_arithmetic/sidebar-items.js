window.SIDEBAR_ITEMS = {"fn":[["be_U32_to_seq","Converts a U32 to Seq"],["be_seq_add","Adds two byte sequences of any length "],["be_seq_div","Makes integer division on two byte sequences of any length and returns (quotient, remainder) Returns 0 when trying to divide by 0 TODO: Give error when dividing by 0"],["be_seq_exp","Calculates exponents NOTE: only supports exponents of max size usize TODO: Add support of any size exponents, perhaps put loops in a seperate function that supports loops to a byteSeq max"],["be_seq_mod",""],["be_seq_mod_exp","Performs modular exponentiation i. e. a^b mod n Is designed to avoid extremely large intermediate values Uses the square multiply algorithm"],["be_seq_mul","Mulitplies two byte sequences of any length and returns the product"],["be_seq_mul_mod",""],["be_seq_sub","Subtracts two byte sequences of any length, returns result as well as bool stating if theres underflow or not"],["be_seq_trim","Trims a byte sequence by removing leading zeroes. Returns the trimmed byte sequence"],["seq_eq","Trims and compares two byte sequences, returns true if equal "],["seq_leq","Returns true if a is less or equal to b"],["seq_one","returns byte sequence with value one"],["seq_shift_left","Adds n trailing bytes with value zero to a"],["seq_shift_right","Adds n leading bytes with value zero to a"],["seq_to_U128","Converts a byte sequence to a U128 "],["seq_to_usize","Converts a byte sequence to usize"],["seq_zero","returns byte sequence with value zero"]]};