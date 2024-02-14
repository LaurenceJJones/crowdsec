// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
)

// DecisionUpdate is the builder for updating Decision entities.
type DecisionUpdate struct {
	config
	hooks    []Hook
	mutation *DecisionMutation
}

// Where appends a list predicates to the DecisionUpdate builder.
func (du *DecisionUpdate) Where(ps ...predicate.Decision) *DecisionUpdate {
	du.mutation.Where(ps...)
	return du
}

// SetCreatedAt sets the "created_at" field.
func (du *DecisionUpdate) SetCreatedAt(t time.Time) *DecisionUpdate {
	du.mutation.SetCreatedAt(t)
	return du
}

// ClearCreatedAt clears the value of the "created_at" field.
func (du *DecisionUpdate) ClearCreatedAt() *DecisionUpdate {
	du.mutation.ClearCreatedAt()
	return du
}

// SetUpdatedAt sets the "updated_at" field.
func (du *DecisionUpdate) SetUpdatedAt(t time.Time) *DecisionUpdate {
	du.mutation.SetUpdatedAt(t)
	return du
}

// ClearUpdatedAt clears the value of the "updated_at" field.
func (du *DecisionUpdate) ClearUpdatedAt() *DecisionUpdate {
	du.mutation.ClearUpdatedAt()
	return du
}

// SetUntil sets the "until" field.
func (du *DecisionUpdate) SetUntil(t time.Time) *DecisionUpdate {
	du.mutation.SetUntil(t)
	return du
}

// SetNillableUntil sets the "until" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableUntil(t *time.Time) *DecisionUpdate {
	if t != nil {
		du.SetUntil(*t)
	}
	return du
}

// ClearUntil clears the value of the "until" field.
func (du *DecisionUpdate) ClearUntil() *DecisionUpdate {
	du.mutation.ClearUntil()
	return du
}

// SetScenario sets the "scenario" field.
func (du *DecisionUpdate) SetScenario(s string) *DecisionUpdate {
	du.mutation.SetScenario(s)
	return du
}

// SetType sets the "type" field.
func (du *DecisionUpdate) SetType(s string) *DecisionUpdate {
	du.mutation.SetType(s)
	return du
}

// SetStartIP sets the "start_ip" field.
func (du *DecisionUpdate) SetStartIP(i int64) *DecisionUpdate {
	du.mutation.ResetStartIP()
	du.mutation.SetStartIP(i)
	return du
}

// SetNillableStartIP sets the "start_ip" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableStartIP(i *int64) *DecisionUpdate {
	if i != nil {
		du.SetStartIP(*i)
	}
	return du
}

// AddStartIP adds i to the "start_ip" field.
func (du *DecisionUpdate) AddStartIP(i int64) *DecisionUpdate {
	du.mutation.AddStartIP(i)
	return du
}

// ClearStartIP clears the value of the "start_ip" field.
func (du *DecisionUpdate) ClearStartIP() *DecisionUpdate {
	du.mutation.ClearStartIP()
	return du
}

// SetEndIP sets the "end_ip" field.
func (du *DecisionUpdate) SetEndIP(i int64) *DecisionUpdate {
	du.mutation.ResetEndIP()
	du.mutation.SetEndIP(i)
	return du
}

// SetNillableEndIP sets the "end_ip" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableEndIP(i *int64) *DecisionUpdate {
	if i != nil {
		du.SetEndIP(*i)
	}
	return du
}

// AddEndIP adds i to the "end_ip" field.
func (du *DecisionUpdate) AddEndIP(i int64) *DecisionUpdate {
	du.mutation.AddEndIP(i)
	return du
}

// ClearEndIP clears the value of the "end_ip" field.
func (du *DecisionUpdate) ClearEndIP() *DecisionUpdate {
	du.mutation.ClearEndIP()
	return du
}

// SetStartSuffix sets the "start_suffix" field.
func (du *DecisionUpdate) SetStartSuffix(i int64) *DecisionUpdate {
	du.mutation.ResetStartSuffix()
	du.mutation.SetStartSuffix(i)
	return du
}

// SetNillableStartSuffix sets the "start_suffix" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableStartSuffix(i *int64) *DecisionUpdate {
	if i != nil {
		du.SetStartSuffix(*i)
	}
	return du
}

// AddStartSuffix adds i to the "start_suffix" field.
func (du *DecisionUpdate) AddStartSuffix(i int64) *DecisionUpdate {
	du.mutation.AddStartSuffix(i)
	return du
}

// ClearStartSuffix clears the value of the "start_suffix" field.
func (du *DecisionUpdate) ClearStartSuffix() *DecisionUpdate {
	du.mutation.ClearStartSuffix()
	return du
}

// SetEndSuffix sets the "end_suffix" field.
func (du *DecisionUpdate) SetEndSuffix(i int64) *DecisionUpdate {
	du.mutation.ResetEndSuffix()
	du.mutation.SetEndSuffix(i)
	return du
}

// SetNillableEndSuffix sets the "end_suffix" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableEndSuffix(i *int64) *DecisionUpdate {
	if i != nil {
		du.SetEndSuffix(*i)
	}
	return du
}

// AddEndSuffix adds i to the "end_suffix" field.
func (du *DecisionUpdate) AddEndSuffix(i int64) *DecisionUpdate {
	du.mutation.AddEndSuffix(i)
	return du
}

// ClearEndSuffix clears the value of the "end_suffix" field.
func (du *DecisionUpdate) ClearEndSuffix() *DecisionUpdate {
	du.mutation.ClearEndSuffix()
	return du
}

// SetIPSize sets the "ip_size" field.
func (du *DecisionUpdate) SetIPSize(i int64) *DecisionUpdate {
	du.mutation.ResetIPSize()
	du.mutation.SetIPSize(i)
	return du
}

// SetNillableIPSize sets the "ip_size" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableIPSize(i *int64) *DecisionUpdate {
	if i != nil {
		du.SetIPSize(*i)
	}
	return du
}

// AddIPSize adds i to the "ip_size" field.
func (du *DecisionUpdate) AddIPSize(i int64) *DecisionUpdate {
	du.mutation.AddIPSize(i)
	return du
}

// ClearIPSize clears the value of the "ip_size" field.
func (du *DecisionUpdate) ClearIPSize() *DecisionUpdate {
	du.mutation.ClearIPSize()
	return du
}

// SetScope sets the "scope" field.
func (du *DecisionUpdate) SetScope(s string) *DecisionUpdate {
	du.mutation.SetScope(s)
	return du
}

// SetValue sets the "value" field.
func (du *DecisionUpdate) SetValue(s string) *DecisionUpdate {
	du.mutation.SetValue(s)
	return du
}

// SetOrigin sets the "origin" field.
func (du *DecisionUpdate) SetOrigin(s string) *DecisionUpdate {
	du.mutation.SetOrigin(s)
	return du
}

// SetSimulated sets the "simulated" field.
func (du *DecisionUpdate) SetSimulated(b bool) *DecisionUpdate {
	du.mutation.SetSimulated(b)
	return du
}

// SetNillableSimulated sets the "simulated" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableSimulated(b *bool) *DecisionUpdate {
	if b != nil {
		du.SetSimulated(*b)
	}
	return du
}

// SetUUID sets the "uuid" field.
func (du *DecisionUpdate) SetUUID(s string) *DecisionUpdate {
	du.mutation.SetUUID(s)
	return du
}

// SetNillableUUID sets the "uuid" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableUUID(s *string) *DecisionUpdate {
	if s != nil {
		du.SetUUID(*s)
	}
	return du
}

// ClearUUID clears the value of the "uuid" field.
func (du *DecisionUpdate) ClearUUID() *DecisionUpdate {
	du.mutation.ClearUUID()
	return du
}

// SetAlertDecisions sets the "alert_decisions" field.
func (du *DecisionUpdate) SetAlertDecisions(i int) *DecisionUpdate {
	du.mutation.SetAlertDecisions(i)
	return du
}

// SetNillableAlertDecisions sets the "alert_decisions" field if the given value is not nil.
func (du *DecisionUpdate) SetNillableAlertDecisions(i *int) *DecisionUpdate {
	if i != nil {
		du.SetAlertDecisions(*i)
	}
	return du
}

// ClearAlertDecisions clears the value of the "alert_decisions" field.
func (du *DecisionUpdate) ClearAlertDecisions() *DecisionUpdate {
	du.mutation.ClearAlertDecisions()
	return du
}

// SetOwnerID sets the "owner" edge to the Alert entity by ID.
func (du *DecisionUpdate) SetOwnerID(id int) *DecisionUpdate {
	du.mutation.SetOwnerID(id)
	return du
}

// SetNillableOwnerID sets the "owner" edge to the Alert entity by ID if the given value is not nil.
func (du *DecisionUpdate) SetNillableOwnerID(id *int) *DecisionUpdate {
	if id != nil {
		du = du.SetOwnerID(*id)
	}
	return du
}

// SetOwner sets the "owner" edge to the Alert entity.
func (du *DecisionUpdate) SetOwner(a *Alert) *DecisionUpdate {
	return du.SetOwnerID(a.ID)
}

// Mutation returns the DecisionMutation object of the builder.
func (du *DecisionUpdate) Mutation() *DecisionMutation {
	return du.mutation
}

// ClearOwner clears the "owner" edge to the Alert entity.
func (du *DecisionUpdate) ClearOwner() *DecisionUpdate {
	du.mutation.ClearOwner()
	return du
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (du *DecisionUpdate) Save(ctx context.Context) (int, error) {
	du.defaults()
	return withHooks(ctx, du.sqlSave, du.mutation, du.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (du *DecisionUpdate) SaveX(ctx context.Context) int {
	affected, err := du.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (du *DecisionUpdate) Exec(ctx context.Context) error {
	_, err := du.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (du *DecisionUpdate) ExecX(ctx context.Context) {
	if err := du.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (du *DecisionUpdate) defaults() {
	if _, ok := du.mutation.CreatedAt(); !ok && !du.mutation.CreatedAtCleared() {
		v := decision.UpdateDefaultCreatedAt()
		du.mutation.SetCreatedAt(v)
	}
	if _, ok := du.mutation.UpdatedAt(); !ok && !du.mutation.UpdatedAtCleared() {
		v := decision.UpdateDefaultUpdatedAt()
		du.mutation.SetUpdatedAt(v)
	}
}

func (du *DecisionUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(decision.Table, decision.Columns, sqlgraph.NewFieldSpec(decision.FieldID, field.TypeInt))
	if ps := du.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := du.mutation.CreatedAt(); ok {
		_spec.SetField(decision.FieldCreatedAt, field.TypeTime, value)
	}
	if du.mutation.CreatedAtCleared() {
		_spec.ClearField(decision.FieldCreatedAt, field.TypeTime)
	}
	if value, ok := du.mutation.UpdatedAt(); ok {
		_spec.SetField(decision.FieldUpdatedAt, field.TypeTime, value)
	}
	if du.mutation.UpdatedAtCleared() {
		_spec.ClearField(decision.FieldUpdatedAt, field.TypeTime)
	}
	if value, ok := du.mutation.Until(); ok {
		_spec.SetField(decision.FieldUntil, field.TypeTime, value)
	}
	if du.mutation.UntilCleared() {
		_spec.ClearField(decision.FieldUntil, field.TypeTime)
	}
	if value, ok := du.mutation.Scenario(); ok {
		_spec.SetField(decision.FieldScenario, field.TypeString, value)
	}
	if value, ok := du.mutation.GetType(); ok {
		_spec.SetField(decision.FieldType, field.TypeString, value)
	}
	if value, ok := du.mutation.StartIP(); ok {
		_spec.SetField(decision.FieldStartIP, field.TypeInt64, value)
	}
	if value, ok := du.mutation.AddedStartIP(); ok {
		_spec.AddField(decision.FieldStartIP, field.TypeInt64, value)
	}
	if du.mutation.StartIPCleared() {
		_spec.ClearField(decision.FieldStartIP, field.TypeInt64)
	}
	if value, ok := du.mutation.EndIP(); ok {
		_spec.SetField(decision.FieldEndIP, field.TypeInt64, value)
	}
	if value, ok := du.mutation.AddedEndIP(); ok {
		_spec.AddField(decision.FieldEndIP, field.TypeInt64, value)
	}
	if du.mutation.EndIPCleared() {
		_spec.ClearField(decision.FieldEndIP, field.TypeInt64)
	}
	if value, ok := du.mutation.StartSuffix(); ok {
		_spec.SetField(decision.FieldStartSuffix, field.TypeInt64, value)
	}
	if value, ok := du.mutation.AddedStartSuffix(); ok {
		_spec.AddField(decision.FieldStartSuffix, field.TypeInt64, value)
	}
	if du.mutation.StartSuffixCleared() {
		_spec.ClearField(decision.FieldStartSuffix, field.TypeInt64)
	}
	if value, ok := du.mutation.EndSuffix(); ok {
		_spec.SetField(decision.FieldEndSuffix, field.TypeInt64, value)
	}
	if value, ok := du.mutation.AddedEndSuffix(); ok {
		_spec.AddField(decision.FieldEndSuffix, field.TypeInt64, value)
	}
	if du.mutation.EndSuffixCleared() {
		_spec.ClearField(decision.FieldEndSuffix, field.TypeInt64)
	}
	if value, ok := du.mutation.IPSize(); ok {
		_spec.SetField(decision.FieldIPSize, field.TypeInt64, value)
	}
	if value, ok := du.mutation.AddedIPSize(); ok {
		_spec.AddField(decision.FieldIPSize, field.TypeInt64, value)
	}
	if du.mutation.IPSizeCleared() {
		_spec.ClearField(decision.FieldIPSize, field.TypeInt64)
	}
	if value, ok := du.mutation.Scope(); ok {
		_spec.SetField(decision.FieldScope, field.TypeString, value)
	}
	if value, ok := du.mutation.Value(); ok {
		_spec.SetField(decision.FieldValue, field.TypeString, value)
	}
	if value, ok := du.mutation.Origin(); ok {
		_spec.SetField(decision.FieldOrigin, field.TypeString, value)
	}
	if value, ok := du.mutation.Simulated(); ok {
		_spec.SetField(decision.FieldSimulated, field.TypeBool, value)
	}
	if value, ok := du.mutation.UUID(); ok {
		_spec.SetField(decision.FieldUUID, field.TypeString, value)
	}
	if du.mutation.UUIDCleared() {
		_spec.ClearField(decision.FieldUUID, field.TypeString)
	}
	if du.mutation.OwnerCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   decision.OwnerTable,
			Columns: []string{decision.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(alert.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := du.mutation.OwnerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   decision.OwnerTable,
			Columns: []string{decision.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(alert.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, du.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{decision.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	du.mutation.done = true
	return n, nil
}

// DecisionUpdateOne is the builder for updating a single Decision entity.
type DecisionUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *DecisionMutation
}

// SetCreatedAt sets the "created_at" field.
func (duo *DecisionUpdateOne) SetCreatedAt(t time.Time) *DecisionUpdateOne {
	duo.mutation.SetCreatedAt(t)
	return duo
}

// ClearCreatedAt clears the value of the "created_at" field.
func (duo *DecisionUpdateOne) ClearCreatedAt() *DecisionUpdateOne {
	duo.mutation.ClearCreatedAt()
	return duo
}

// SetUpdatedAt sets the "updated_at" field.
func (duo *DecisionUpdateOne) SetUpdatedAt(t time.Time) *DecisionUpdateOne {
	duo.mutation.SetUpdatedAt(t)
	return duo
}

// ClearUpdatedAt clears the value of the "updated_at" field.
func (duo *DecisionUpdateOne) ClearUpdatedAt() *DecisionUpdateOne {
	duo.mutation.ClearUpdatedAt()
	return duo
}

// SetUntil sets the "until" field.
func (duo *DecisionUpdateOne) SetUntil(t time.Time) *DecisionUpdateOne {
	duo.mutation.SetUntil(t)
	return duo
}

// SetNillableUntil sets the "until" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableUntil(t *time.Time) *DecisionUpdateOne {
	if t != nil {
		duo.SetUntil(*t)
	}
	return duo
}

// ClearUntil clears the value of the "until" field.
func (duo *DecisionUpdateOne) ClearUntil() *DecisionUpdateOne {
	duo.mutation.ClearUntil()
	return duo
}

// SetScenario sets the "scenario" field.
func (duo *DecisionUpdateOne) SetScenario(s string) *DecisionUpdateOne {
	duo.mutation.SetScenario(s)
	return duo
}

// SetType sets the "type" field.
func (duo *DecisionUpdateOne) SetType(s string) *DecisionUpdateOne {
	duo.mutation.SetType(s)
	return duo
}

// SetStartIP sets the "start_ip" field.
func (duo *DecisionUpdateOne) SetStartIP(i int64) *DecisionUpdateOne {
	duo.mutation.ResetStartIP()
	duo.mutation.SetStartIP(i)
	return duo
}

// SetNillableStartIP sets the "start_ip" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableStartIP(i *int64) *DecisionUpdateOne {
	if i != nil {
		duo.SetStartIP(*i)
	}
	return duo
}

// AddStartIP adds i to the "start_ip" field.
func (duo *DecisionUpdateOne) AddStartIP(i int64) *DecisionUpdateOne {
	duo.mutation.AddStartIP(i)
	return duo
}

// ClearStartIP clears the value of the "start_ip" field.
func (duo *DecisionUpdateOne) ClearStartIP() *DecisionUpdateOne {
	duo.mutation.ClearStartIP()
	return duo
}

// SetEndIP sets the "end_ip" field.
func (duo *DecisionUpdateOne) SetEndIP(i int64) *DecisionUpdateOne {
	duo.mutation.ResetEndIP()
	duo.mutation.SetEndIP(i)
	return duo
}

// SetNillableEndIP sets the "end_ip" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableEndIP(i *int64) *DecisionUpdateOne {
	if i != nil {
		duo.SetEndIP(*i)
	}
	return duo
}

// AddEndIP adds i to the "end_ip" field.
func (duo *DecisionUpdateOne) AddEndIP(i int64) *DecisionUpdateOne {
	duo.mutation.AddEndIP(i)
	return duo
}

// ClearEndIP clears the value of the "end_ip" field.
func (duo *DecisionUpdateOne) ClearEndIP() *DecisionUpdateOne {
	duo.mutation.ClearEndIP()
	return duo
}

// SetStartSuffix sets the "start_suffix" field.
func (duo *DecisionUpdateOne) SetStartSuffix(i int64) *DecisionUpdateOne {
	duo.mutation.ResetStartSuffix()
	duo.mutation.SetStartSuffix(i)
	return duo
}

// SetNillableStartSuffix sets the "start_suffix" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableStartSuffix(i *int64) *DecisionUpdateOne {
	if i != nil {
		duo.SetStartSuffix(*i)
	}
	return duo
}

// AddStartSuffix adds i to the "start_suffix" field.
func (duo *DecisionUpdateOne) AddStartSuffix(i int64) *DecisionUpdateOne {
	duo.mutation.AddStartSuffix(i)
	return duo
}

// ClearStartSuffix clears the value of the "start_suffix" field.
func (duo *DecisionUpdateOne) ClearStartSuffix() *DecisionUpdateOne {
	duo.mutation.ClearStartSuffix()
	return duo
}

// SetEndSuffix sets the "end_suffix" field.
func (duo *DecisionUpdateOne) SetEndSuffix(i int64) *DecisionUpdateOne {
	duo.mutation.ResetEndSuffix()
	duo.mutation.SetEndSuffix(i)
	return duo
}

// SetNillableEndSuffix sets the "end_suffix" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableEndSuffix(i *int64) *DecisionUpdateOne {
	if i != nil {
		duo.SetEndSuffix(*i)
	}
	return duo
}

// AddEndSuffix adds i to the "end_suffix" field.
func (duo *DecisionUpdateOne) AddEndSuffix(i int64) *DecisionUpdateOne {
	duo.mutation.AddEndSuffix(i)
	return duo
}

// ClearEndSuffix clears the value of the "end_suffix" field.
func (duo *DecisionUpdateOne) ClearEndSuffix() *DecisionUpdateOne {
	duo.mutation.ClearEndSuffix()
	return duo
}

// SetIPSize sets the "ip_size" field.
func (duo *DecisionUpdateOne) SetIPSize(i int64) *DecisionUpdateOne {
	duo.mutation.ResetIPSize()
	duo.mutation.SetIPSize(i)
	return duo
}

// SetNillableIPSize sets the "ip_size" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableIPSize(i *int64) *DecisionUpdateOne {
	if i != nil {
		duo.SetIPSize(*i)
	}
	return duo
}

// AddIPSize adds i to the "ip_size" field.
func (duo *DecisionUpdateOne) AddIPSize(i int64) *DecisionUpdateOne {
	duo.mutation.AddIPSize(i)
	return duo
}

// ClearIPSize clears the value of the "ip_size" field.
func (duo *DecisionUpdateOne) ClearIPSize() *DecisionUpdateOne {
	duo.mutation.ClearIPSize()
	return duo
}

// SetScope sets the "scope" field.
func (duo *DecisionUpdateOne) SetScope(s string) *DecisionUpdateOne {
	duo.mutation.SetScope(s)
	return duo
}

// SetValue sets the "value" field.
func (duo *DecisionUpdateOne) SetValue(s string) *DecisionUpdateOne {
	duo.mutation.SetValue(s)
	return duo
}

// SetOrigin sets the "origin" field.
func (duo *DecisionUpdateOne) SetOrigin(s string) *DecisionUpdateOne {
	duo.mutation.SetOrigin(s)
	return duo
}

// SetSimulated sets the "simulated" field.
func (duo *DecisionUpdateOne) SetSimulated(b bool) *DecisionUpdateOne {
	duo.mutation.SetSimulated(b)
	return duo
}

// SetNillableSimulated sets the "simulated" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableSimulated(b *bool) *DecisionUpdateOne {
	if b != nil {
		duo.SetSimulated(*b)
	}
	return duo
}

// SetUUID sets the "uuid" field.
func (duo *DecisionUpdateOne) SetUUID(s string) *DecisionUpdateOne {
	duo.mutation.SetUUID(s)
	return duo
}

// SetNillableUUID sets the "uuid" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableUUID(s *string) *DecisionUpdateOne {
	if s != nil {
		duo.SetUUID(*s)
	}
	return duo
}

// ClearUUID clears the value of the "uuid" field.
func (duo *DecisionUpdateOne) ClearUUID() *DecisionUpdateOne {
	duo.mutation.ClearUUID()
	return duo
}

// SetAlertDecisions sets the "alert_decisions" field.
func (duo *DecisionUpdateOne) SetAlertDecisions(i int) *DecisionUpdateOne {
	duo.mutation.SetAlertDecisions(i)
	return duo
}

// SetNillableAlertDecisions sets the "alert_decisions" field if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableAlertDecisions(i *int) *DecisionUpdateOne {
	if i != nil {
		duo.SetAlertDecisions(*i)
	}
	return duo
}

// ClearAlertDecisions clears the value of the "alert_decisions" field.
func (duo *DecisionUpdateOne) ClearAlertDecisions() *DecisionUpdateOne {
	duo.mutation.ClearAlertDecisions()
	return duo
}

// SetOwnerID sets the "owner" edge to the Alert entity by ID.
func (duo *DecisionUpdateOne) SetOwnerID(id int) *DecisionUpdateOne {
	duo.mutation.SetOwnerID(id)
	return duo
}

// SetNillableOwnerID sets the "owner" edge to the Alert entity by ID if the given value is not nil.
func (duo *DecisionUpdateOne) SetNillableOwnerID(id *int) *DecisionUpdateOne {
	if id != nil {
		duo = duo.SetOwnerID(*id)
	}
	return duo
}

// SetOwner sets the "owner" edge to the Alert entity.
func (duo *DecisionUpdateOne) SetOwner(a *Alert) *DecisionUpdateOne {
	return duo.SetOwnerID(a.ID)
}

// Mutation returns the DecisionMutation object of the builder.
func (duo *DecisionUpdateOne) Mutation() *DecisionMutation {
	return duo.mutation
}

// ClearOwner clears the "owner" edge to the Alert entity.
func (duo *DecisionUpdateOne) ClearOwner() *DecisionUpdateOne {
	duo.mutation.ClearOwner()
	return duo
}

// Where appends a list predicates to the DecisionUpdate builder.
func (duo *DecisionUpdateOne) Where(ps ...predicate.Decision) *DecisionUpdateOne {
	duo.mutation.Where(ps...)
	return duo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (duo *DecisionUpdateOne) Select(field string, fields ...string) *DecisionUpdateOne {
	duo.fields = append([]string{field}, fields...)
	return duo
}

// Save executes the query and returns the updated Decision entity.
func (duo *DecisionUpdateOne) Save(ctx context.Context) (*Decision, error) {
	duo.defaults()
	return withHooks(ctx, duo.sqlSave, duo.mutation, duo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (duo *DecisionUpdateOne) SaveX(ctx context.Context) *Decision {
	node, err := duo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (duo *DecisionUpdateOne) Exec(ctx context.Context) error {
	_, err := duo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (duo *DecisionUpdateOne) ExecX(ctx context.Context) {
	if err := duo.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (duo *DecisionUpdateOne) defaults() {
	if _, ok := duo.mutation.CreatedAt(); !ok && !duo.mutation.CreatedAtCleared() {
		v := decision.UpdateDefaultCreatedAt()
		duo.mutation.SetCreatedAt(v)
	}
	if _, ok := duo.mutation.UpdatedAt(); !ok && !duo.mutation.UpdatedAtCleared() {
		v := decision.UpdateDefaultUpdatedAt()
		duo.mutation.SetUpdatedAt(v)
	}
}

func (duo *DecisionUpdateOne) sqlSave(ctx context.Context) (_node *Decision, err error) {
	_spec := sqlgraph.NewUpdateSpec(decision.Table, decision.Columns, sqlgraph.NewFieldSpec(decision.FieldID, field.TypeInt))
	id, ok := duo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Decision.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := duo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, decision.FieldID)
		for _, f := range fields {
			if !decision.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != decision.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := duo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := duo.mutation.CreatedAt(); ok {
		_spec.SetField(decision.FieldCreatedAt, field.TypeTime, value)
	}
	if duo.mutation.CreatedAtCleared() {
		_spec.ClearField(decision.FieldCreatedAt, field.TypeTime)
	}
	if value, ok := duo.mutation.UpdatedAt(); ok {
		_spec.SetField(decision.FieldUpdatedAt, field.TypeTime, value)
	}
	if duo.mutation.UpdatedAtCleared() {
		_spec.ClearField(decision.FieldUpdatedAt, field.TypeTime)
	}
	if value, ok := duo.mutation.Until(); ok {
		_spec.SetField(decision.FieldUntil, field.TypeTime, value)
	}
	if duo.mutation.UntilCleared() {
		_spec.ClearField(decision.FieldUntil, field.TypeTime)
	}
	if value, ok := duo.mutation.Scenario(); ok {
		_spec.SetField(decision.FieldScenario, field.TypeString, value)
	}
	if value, ok := duo.mutation.GetType(); ok {
		_spec.SetField(decision.FieldType, field.TypeString, value)
	}
	if value, ok := duo.mutation.StartIP(); ok {
		_spec.SetField(decision.FieldStartIP, field.TypeInt64, value)
	}
	if value, ok := duo.mutation.AddedStartIP(); ok {
		_spec.AddField(decision.FieldStartIP, field.TypeInt64, value)
	}
	if duo.mutation.StartIPCleared() {
		_spec.ClearField(decision.FieldStartIP, field.TypeInt64)
	}
	if value, ok := duo.mutation.EndIP(); ok {
		_spec.SetField(decision.FieldEndIP, field.TypeInt64, value)
	}
	if value, ok := duo.mutation.AddedEndIP(); ok {
		_spec.AddField(decision.FieldEndIP, field.TypeInt64, value)
	}
	if duo.mutation.EndIPCleared() {
		_spec.ClearField(decision.FieldEndIP, field.TypeInt64)
	}
	if value, ok := duo.mutation.StartSuffix(); ok {
		_spec.SetField(decision.FieldStartSuffix, field.TypeInt64, value)
	}
	if value, ok := duo.mutation.AddedStartSuffix(); ok {
		_spec.AddField(decision.FieldStartSuffix, field.TypeInt64, value)
	}
	if duo.mutation.StartSuffixCleared() {
		_spec.ClearField(decision.FieldStartSuffix, field.TypeInt64)
	}
	if value, ok := duo.mutation.EndSuffix(); ok {
		_spec.SetField(decision.FieldEndSuffix, field.TypeInt64, value)
	}
	if value, ok := duo.mutation.AddedEndSuffix(); ok {
		_spec.AddField(decision.FieldEndSuffix, field.TypeInt64, value)
	}
	if duo.mutation.EndSuffixCleared() {
		_spec.ClearField(decision.FieldEndSuffix, field.TypeInt64)
	}
	if value, ok := duo.mutation.IPSize(); ok {
		_spec.SetField(decision.FieldIPSize, field.TypeInt64, value)
	}
	if value, ok := duo.mutation.AddedIPSize(); ok {
		_spec.AddField(decision.FieldIPSize, field.TypeInt64, value)
	}
	if duo.mutation.IPSizeCleared() {
		_spec.ClearField(decision.FieldIPSize, field.TypeInt64)
	}
	if value, ok := duo.mutation.Scope(); ok {
		_spec.SetField(decision.FieldScope, field.TypeString, value)
	}
	if value, ok := duo.mutation.Value(); ok {
		_spec.SetField(decision.FieldValue, field.TypeString, value)
	}
	if value, ok := duo.mutation.Origin(); ok {
		_spec.SetField(decision.FieldOrigin, field.TypeString, value)
	}
	if value, ok := duo.mutation.Simulated(); ok {
		_spec.SetField(decision.FieldSimulated, field.TypeBool, value)
	}
	if value, ok := duo.mutation.UUID(); ok {
		_spec.SetField(decision.FieldUUID, field.TypeString, value)
	}
	if duo.mutation.UUIDCleared() {
		_spec.ClearField(decision.FieldUUID, field.TypeString)
	}
	if duo.mutation.OwnerCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   decision.OwnerTable,
			Columns: []string{decision.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(alert.FieldID, field.TypeInt),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := duo.mutation.OwnerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   decision.OwnerTable,
			Columns: []string{decision.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(alert.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &Decision{config: duo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, duo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{decision.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	duo.mutation.done = true
	return _node, nil
}
