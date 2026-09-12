package cli

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A setting the agent takes but section has no field for is one that
// 'cheesecloth config' drops without saying so, and that no config file can
// hold. The two are written out separately, so this is what keeps them in
// step: a new flag fails here until it is given somewhere to be written.
func Test_section_holdsEverySetting(t *testing.T) {
	// The interface is the section name rather than a setting in it, so it is
	// the one field of settings that section must not have.
	const sectionName = "Interface"

	inSection := map[string]bool{}
	sectionType := reflect.TypeFor[section]()
	for i := range sectionType.NumField() {
		inSection[sectionType.Field(i).Name] = true
	}

	settingsType := reflect.TypeFor[settings]()
	for i := range settingsType.NumField() {
		f := settingsType.Field(i)
		if !f.IsExported() {
			continue // stateDir and the like: not settings
		}
		if f.Name == sectionName {
			assert.False(t, inSection[f.Name], "%s is the section's name, not a setting in it", f.Name)
			continue
		}
		assert.True(t, inSection[f.Name], "settings.%s has no section field, so 'cheesecloth config' cannot write it", f.Name)
	}
}

// Every section field is a setting, a flag name the config file accepts, or
// the file would hold a key no command reads.
func Test_section_holdsNothingElse(t *testing.T) {
	// LogLevel is a global flag rather than one of an interface's settings,
	// but it belongs to a section all the same: the agent runs one interface.
	const global = "LogLevel"

	inSettings := map[string]bool{}
	settingsType := reflect.TypeFor[settings]()
	for i := range settingsType.NumField() {
		inSettings[settingsType.Field(i).Name] = true
	}

	sectionType := reflect.TypeFor[section]()
	for i := range sectionType.NumField() {
		name := sectionType.Field(i).Name
		if name == global {
			continue
		}
		assert.True(t, inSettings[name], "section.%s is not a setting the agent takes", name)
	}
}
