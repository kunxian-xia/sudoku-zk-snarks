//
// Created by xkx on 11/1/18.
//

#define CURVE_ALT_BN128

#include "sudoku_gadget.hpp"
#include <libff/common/default_types/ec_pp.hpp>
#include <iostream>

int main() {
    libff::default_ec_pp::init_public_params();

    typedef libff::Fr<libff::default_ec_pp> FieldT;
    protoboard<FieldT> pb;
    sudoku_gadget<FieldT> gadget(pb, "sudoku gadget");

    gadget.generate_r1cs_constraints();
    std::cout << pb.num_constraints() << std::endl;
}