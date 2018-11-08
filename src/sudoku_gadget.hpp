#ifndef _SUDOKU_GADGET_HPP
#define _SUDOKU_GADGET_HPP

#include <libsnark/gadgetlib1/gadget.hpp>
#include <memory>

using namespace libsnark;

/*
 * validate Input comes from the set {v1, ..., vn}
 * equivalent to constraint (x - v1) ... (x - vn) = 0
 */
template<typename FieldT>
class validateInput_gadget : public gadget<FieldT> {
private:
public:
    std::vector<int> values;
    pb_variable<FieldT> x;
    pb_variable_array<FieldT> intermediates;

    validateInput_gadget(protoboard<FieldT> &pb,
                         const pb_variable<FieldT> &x,
                         const std::vector<int> &values,
                         const std::string &annotation_prefix = "validate Input") :
            gadget<FieldT>(pb, annotation_prefix), x(x), values(values) {
        intermediates.allocate(pb, values.size() - 1, FMT(annotation_prefix, "intermediates"));
    }

    void generate_r1cs_constraints() {
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                {ONE * (-values[0]), x},
                {ONE * (-values[1]), x},
                {intermediates[0]}));

        for (size_t i = 1; i < values.size() - 1; i++) {
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                    { ONE * (-values[i]), x},
                    { intermediates[i-1] },
                    { intermediates[i] }));
        }
    }

    void generate_r1cs_witness() {
        FieldT _x = this->pb.val(x);
        this->pb.val(intermediates[0]) = FieldT((_x - values[0]) * (_x - values[1]));
        for (size_t i = 1; i < values.size() - 1; i++) {
            this->pb.val(intermediates[i]) = this->pb.val(intermediates[i - 1]) * (_x - values[i]);
        }
    }
};

/*
 * validate that the elements in inputs are different from each other
 * which is equivalent to the constraint that \prod (inputs[i] - inputs[j]) * inv = 1
 */
template<typename FieldT>
class checkEquality_gadget : public gadget<FieldT> {
private:
public:
    pb_variable<FieldT> inv;
    pb_variable_array<FieldT> inputs;
    pb_variable_array<FieldT> intermediates;

    checkEquality_gadget(protoboard<FieldT> &pb,
                         const pb_variable_array<FieldT> &inputs,
                         const std::string &annotation_prefix = "checkEquality") :
            gadget<FieldT>(pb, annotation_prefix), inputs(inputs) {

        inv.allocate(pb, FMT(annotation_prefix, "inv"));

        int num = inputs.size() * (inputs.size() - 1) / 2;
        intermediates.allocate(pb, num, FMT(annotation_prefix, "intermediates"));
    }

    void generate_r1cs_constraints() {
        size_t counter = 0;
        for (size_t i = 0; i < inputs.size() - 1; i++) {
            for (size_t j = i + 1; j < inputs.size(); j++) {
                if (i == 0 && j == 1) {
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                            {ONE},
                            {inputs[i], inputs[j] * (-1)},
                            {intermediates[0]}));
                    counter++;
                } else {
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                            {intermediates[counter - 1]},
                            {inputs[i], inputs[j] * (-1)},
                            {intermediates[counter]}
                    ));
                    counter++;
                }
            }
        }

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                {intermediates[intermediates.size() - 1]},
                {inv},
                {ONE}
        ));
    }

    void generate_r1cs_witness() {
        std::vector<FieldT> _inputs(inputs.size());
        for (size_t i = 0; i < inputs.size(); i++) {
            _inputs[i] = this->pb.val(inputs[i]);
        }

        int counter = 0;
        for (size_t i = 0; i < inputs.size(); i++) {
            for (size_t j = i + 1; j < inputs.size(); j++) {
                if (i == 0 && j == 1) {
                    this->pb.val(intermediates[counter]) = _inputs[0] - _inputs[1];
                } else {
                    this->pb.val(intermediates[counter]) = this->pb.val(intermediates[counter - 1]) *
                                                           (_inputs[i] - _inputs[j]);
                }
                counter++;
            }
        }
        this->pb.val(inv) = this->pb.val(intermediates[counter-1]).inverse();
    }
};

/*
 * Verify a 4 x 4 sudoku with the following layout:
 *
 * | a11 | a12 || b11 | b12 |
 * --------------------------
 * | a21 | a22 || b21 | b22 |
 * ==========================
 * | c11 | c12 || d11 | d12 |
 * --------------------------
 * | c21 | c22 || d21 | d22 |
 *
 * This gadget is equivalent to sudokuchecker.code in ZoKrates
 */
template<typename FieldT>
class sudoku_gadget : public gadget<FieldT> {
private:
    /* internal */
public:
    std::vector<std::shared_ptr<validateInput_gadget<FieldT>>> v_inputs;

    std::vector<std::shared_ptr<checkEquality_gadget<FieldT>>> c_rows;
    std::vector<std::shared_ptr<checkEquality_gadget<FieldT>>> c_cols;
    std::vector<std::shared_ptr<checkEquality_gadget<FieldT>>> c_grids;

    pb_variable<FieldT> a11;
    pb_variable<FieldT> a12;
    pb_variable<FieldT> a21;
    pb_variable<FieldT> a22;

    pb_variable<FieldT> b11;
    pb_variable<FieldT> b12;
    pb_variable<FieldT> b21;
    pb_variable<FieldT> b22;

    pb_variable<FieldT> c11;
    pb_variable<FieldT> c12;
    pb_variable<FieldT> c21;
    pb_variable<FieldT> c22;

    pb_variable<FieldT> d11;
    pb_variable<FieldT> d12;
    pb_variable<FieldT> d21;
    pb_variable<FieldT> d22;

    pb_variable<FieldT> zero;

    sudoku_gadget(protoboard<FieldT> &pb, const std::string &annotation_prefix) :
            gadget<FieldT>(pb, annotation_prefix) {

        //primary inputs consist of a21, b11, b22, c11, c22, d21
        a21.allocate(pb, FMT(annotation_prefix, "primary_a21"));
        b11.allocate(pb, FMT(annotation_prefix, "primary_b11"));
        b22.allocate(pb, FMT(annotation_prefix, "primary_b22"));
        c11.allocate(pb, FMT(annotation_prefix, "primary_c11"));
        c22.allocate(pb, FMT(annotation_prefix, "primary_c22"));
        d21.allocate(pb, FMT(annotation_prefix, "primary_d21"));

        zero.allocate(pb, FMT(annotation_prefix, "zero"));
        //auxiliary inputs consist of the remaining 10 elements in the 4 x 4 grid
        a11.allocate(pb, FMT(annotation_prefix, "aux_a11"));
        a12.allocate(pb, FMT(annotation_prefix, "aux_a12"));
        a22.allocate(pb, FMT(annotation_prefix, "aux_a22"));
        b12.allocate(pb, FMT(annotation_prefix, "aux_b12"));
        b21.allocate(pb, FMT(annotation_prefix, "aux_b21"));
        c12.allocate(pb, FMT(annotation_prefix, "aux_c12"));
        c21.allocate(pb, FMT(annotation_prefix, "aux_c21"));
        d11.allocate(pb, FMT(annotation_prefix, "aux_d11"));
        d12.allocate(pb, FMT(annotation_prefix, "aux_d12"));
        d22.allocate(pb, FMT(annotation_prefix, "aux_d22"));

        pb.set_input_sizes(6);

        //input validation
        std::vector<pb_variable<FieldT>> inputs = {a11, a12, a21, a22,
                                                   b11, b12, b21, b22,
                                                   c11, c12, c21, c22,
                                                   d11, d12, d21, d22};
        v_inputs.reserve(16);
        v_inputs.resize(16);
        for (size_t i = 0; i < 16; i++) {
            v_inputs[i].reset(new validateInput_gadget<FieldT>(pb, inputs[i], {1, 2, 3, 4}));
        }

        c_rows.reserve(4); c_rows.resize(4);
        c_cols.reserve(4); c_cols.resize(4);
        c_grids.reserve(4); c_grids.resize(4);

        //row validation
        std::vector<pb_variable<FieldT>> row0 = {a11, a12, b11, b12};
        std::vector<pb_variable<FieldT>> row1 = {a21, a22, b21, b22};
        std::vector<pb_variable<FieldT>> row2 = {c11, c12, d11, d12};
        std::vector<pb_variable<FieldT>> row3 = {c21, c22, d21, d22};

        pb_variable_array<FieldT> _row0(row0.begin(), row0.end());
        pb_variable_array<FieldT> _row1(row1.begin(), row1.end());
        pb_variable_array<FieldT> _row2(row2.begin(), row2.end());
        pb_variable_array<FieldT> _row3(row3.begin(), row3.end());

        c_rows[0].reset(new checkEquality_gadget<FieldT>(pb, _row0));
        c_rows[1].reset(new checkEquality_gadget<FieldT>(pb, _row1));
        c_rows[2].reset(new checkEquality_gadget<FieldT>(pb, _row2));
        c_rows[3].reset(new checkEquality_gadget<FieldT>(pb, _row3));

        //column validation
        std::vector<pb_variable<FieldT>> col0 = {a11, a21, c11, c21};
        std::vector<pb_variable<FieldT>> col1 = {a12, a22, c12, c22};
        std::vector<pb_variable<FieldT>> col2 = {b11, b21, d11, d21};
        std::vector<pb_variable<FieldT>> col3 = {b12, b22, d12, d22};

        pb_variable_array<FieldT> _col0(col0.begin(), col0.end());
        pb_variable_array<FieldT> _col1(col1.begin(), col1.end());
        pb_variable_array<FieldT> _col2(col2.begin(), col2.end());
        pb_variable_array<FieldT> _col3(col3.begin(), col3.end());

        c_cols[0].reset(new checkEquality_gadget<FieldT>(pb, _col0));
        c_cols[1].reset(new checkEquality_gadget<FieldT>(pb, _col1));
        c_cols[2].reset(new checkEquality_gadget<FieldT>(pb, _col2));
        c_cols[3].reset(new checkEquality_gadget<FieldT>(pb, _col3));

        //subgrid validation
        std::vector<pb_variable<FieldT>> grid0 = {a11, a12, a21, a22};
        std::vector<pb_variable<FieldT>> grid1 = {b11, b12, b21, b22};
        std::vector<pb_variable<FieldT>> grid2 = {c11, c12, c21, c22};
        std::vector<pb_variable<FieldT>> grid3 = {d11, d12, d21, d22};

        pb_variable_array<FieldT> _grid0(grid0.begin(), grid0.end());
        pb_variable_array<FieldT> _grid1(grid1.begin(), grid1.end());
        pb_variable_array<FieldT> _grid2(grid2.begin(), grid2.end());
        pb_variable_array<FieldT> _grid3(grid3.begin(), grid3.end());

        c_grids[0].reset(new checkEquality_gadget<FieldT>(pb, _grid0));
        c_grids[1].reset(new checkEquality_gadget<FieldT>(pb, _grid1));
        c_grids[2].reset(new checkEquality_gadget<FieldT>(pb, _grid2));
        c_grids[3].reset(new checkEquality_gadget<FieldT>(pb, _grid3));
    }

    void generate_r1cs_constraints() {
        for (size_t i = 0; i < 16; i++) {
            v_inputs[i]->generate_r1cs_constraints();
        }

        for (size_t i = 0; i < 4; i++) {
            c_rows[i]->generate_r1cs_constraints();
            c_cols[i]->generate_r1cs_constraints();
            c_grids[i]->generate_r1cs_constraints();
        }
    }

    void generate_r1cs_witness(const std::vector<int> &_inputs_a,
                               const std::vector<int> &_inputs_b,
                               const std::vector<int> &_inputs_c,
                               const std::vector<int> &_inputs_d) {
        assert(_inputs_a.size() == 4);
        assert(_inputs_b.size() == 4);
        assert(_inputs_c.size() == 4);
        assert(_inputs_d.size() == 4);

        this->pb.val(a11) = _inputs_a[0];
        this->pb.val(a12) = _inputs_a[1];
        this->pb.val(a21) = _inputs_a[2];
        this->pb.val(a22) = _inputs_a[3];

        this->pb.val(b11) = _inputs_b[0];
        this->pb.val(b12) = _inputs_b[1];
        this->pb.val(b21) = _inputs_b[2];
        this->pb.val(b22) = _inputs_b[3];

        this->pb.val(c11) = _inputs_c[0];
        this->pb.val(c12) = _inputs_c[1];
        this->pb.val(c21) = _inputs_c[2];
        this->pb.val(c22) = _inputs_c[3];

        this->pb.val(d11) = _inputs_d[0];
        this->pb.val(d12) = _inputs_d[1];
        this->pb.val(d21) = _inputs_d[2];
        this->pb.val(d22) = _inputs_d[3];

        for (size_t i = 0; i < 16; i++) {
            v_inputs[i]->generate_r1cs_witness();
        }

        for (size_t i = 0; i < 4; i++) {
            c_rows[i]->generate_r1cs_witness();
            c_cols[i]->generate_r1cs_witness();
            c_grids[i]->generate_r1cs_witness();
        }
    }
};

#endif //_SUDOKU_GADGET_HPP
